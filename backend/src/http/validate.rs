// Reacher - Email Verification
// Copyright (C) 2018-2023 Reacher

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.

// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

//! `GET /` , `GET /health`, and `GET|POST /validate`.
//!
//! Render blocks outbound port 25, so this endpoint does not wait on SMTP
//! unless a SOCKS5 proxy is configured. It still rejects bad syntax and
//! domains with no mail server, which is what actually prevents a bounce
//! from this host.

use check_if_email_exists::misc::check_misc;
use check_if_email_exists::mx::{check_mx, MxDetails};
use check_if_email_exists::smtp::SmtpDetails;
use check_if_email_exists::syntax::check_syntax;
use check_if_email_exists::{check_email, CheckEmailOutput, Reachable, LOG_TARGET};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use warp::{http, Filter};

use super::v0::check_email::post::{with_config, CheckEmailRequest};
use super::{check_header, ReacherResponseError};
use crate::config::BackendConfig;

/// Plain answer for "should this address receive a message?"
#[derive(Debug, PartialEq, Serialize)]
pub struct ValidateResponse {
	pub email: String,
	/// `true` when the mailbox exists, `false` when it does not, `null` when
	/// only the domain could be checked.
	pub exists: Option<bool>,
	/// Send when this is `true`. On Render that means valid syntax and a
	/// domain that accepts mail, because port 25 is blocked.
	pub safe_to_send: bool,
	/// `true` only when we know a message would bounce.
	pub would_bounce: Option<bool>,
	/// `syntax`, `domain`, or `mailbox`.
	pub check_level: String,
	pub mailbox_confirmed: bool,
	pub is_reachable: String,
	/// This endpoint never submits a message.
	pub message_sent: bool,
	pub reason: String,
}

#[derive(Debug, Deserialize)]
struct ValidateBody {
	email: Option<String>,
	to_email: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ValidateQuery {
	email: String,
}

struct Signals<'a> {
	valid_syntax: bool,
	/// `None` means the DNS lookup itself failed.
	accepts_mail: Option<bool>,
	smtp_failed: bool,
	smtp: Option<&'a SmtpDetails>,
	is_disposable: bool,
	is_role_account: bool,
}

fn reachable_label(reachable: Reachable) -> &'static str {
	match reachable {
		Reachable::Safe => "safe",
		Reachable::Risky => "risky",
		Reachable::Invalid => "invalid",
		Reachable::Unknown => "unknown",
	}
}

fn signals_from_output(output: &CheckEmailOutput) -> Signals<'_> {
	let accepts_mail = match &output.mx {
		Err(_) => None,
		Ok(MxDetails { lookup }) => match lookup {
			Ok(records) => Some(records.iter().next().is_some()),
			Err(_) => Some(false),
		},
	};

	let (smtp_failed, smtp) = match &output.smtp {
		Ok(details) => (false, Some(details)),
		Err(_) => (true, None),
	};

	let (is_disposable, is_role_account) = match &output.misc {
		Ok(MiscDetails {
			is_disposable,
			is_role_account,
			..
		}) => (*is_disposable, *is_role_account),
		Err(_) => (false, false),
	};

	Signals {
		valid_syntax: output.syntax.is_valid_syntax,
		accepts_mail,
		smtp_failed,
		smtp,
		is_disposable,
		is_role_account,
	}
}

fn response(
	email: &str,
	reachable: Reachable,
	exists: Option<bool>,
	safe_to_send: bool,
	would_bounce: Option<bool>,
	check_level: &str,
	mailbox_confirmed: bool,
	reason: &str,
) -> ValidateResponse {
	ValidateResponse {
		email: email.to_string(),
		exists,
		safe_to_send,
		would_bounce,
		check_level: check_level.to_string(),
		mailbox_confirmed,
		is_reachable: reachable_label(reachable).to_string(),
		message_sent: false,
		reason: reason.to_string(),
	}
}

fn domain_ok(email: &str, reachable: Reachable, reason: &str) -> ValidateResponse {
	response(
		email,
		reachable,
		None,
		true,
		Some(false),
		"domain",
		false,
		reason,
	)
}

/// Turn a full verification into a yes / no / unknown mailbox answer.
pub fn summarize(output: &CheckEmailOutput) -> ValidateResponse {
	decide(output.input.as_str(), signals_from_output(output))
}

fn decide(email: &str, signals: Signals<'_>) -> ValidateResponse {
	if !signals.valid_syntax {
		return response(
			email,
			Reachable::Invalid,
			Some(false),
			false,
			Some(true),
			"syntax",
			false,
			"The address is not a valid email, so a message to it would bounce.",
		);
	}

	match signals.accepts_mail {
		None => {
			return response(
				email,
				Reachable::Unknown,
				None,
				false,
				None,
				"syntax",
				false,
				"The domain's mail server could not be looked up. Skip this address.",
			);
		}
		Some(false) => {
			return response(
				email,
				Reachable::Invalid,
				Some(false),
				false,
				Some(true),
				"domain",
				false,
				"The domain has no mail server, so a message to it would bounce.",
			);
		}
		Some(true) => {}
	}

	if signals.is_disposable {
		return response(
			email,
			Reachable::Risky,
			None,
			false,
			None,
			"domain",
			false,
			"The domain is a disposable email provider. Skip it to avoid a bounce.",
		);
	}

	let smtp_unreachable = signals.smtp_failed
		|| signals
			.smtp
			.map(|smtp| !smtp.can_connect_smtp)
			.unwrap_or(true);

	if smtp_unreachable {
		let reason = if signals.is_role_account {
			"The domain accepts mail. This host cannot confirm the mailbox because outbound port 25 is blocked. Send it. It is a shared role address such as info@ or support@."
		} else {
			"The domain accepts mail. This host cannot confirm the mailbox because outbound port 25 is blocked. Send it."
		};
		return domain_ok(email, Reachable::Unknown, reason);
	}

	let smtp = signals
		.smtp
		.expect("smtp_unreachable is false, so smtp details are present");

	if smtp.is_disabled || (!smtp.is_deliverable && !smtp.is_catch_all && !smtp.has_full_inbox) {
		return response(
			email,
			Reachable::Invalid,
			Some(false),
			false,
			Some(true),
			"mailbox",
			false,
			"The mailbox does not exist, so a message to it would bounce.",
		);
	}

	if smtp.has_full_inbox {
		return response(
			email,
			Reachable::Risky,
			Some(true),
			false,
			Some(true),
			"mailbox",
			true,
			"The mailbox exists, but the inbox is full, so a message would bounce.",
		);
	}

	if smtp.is_catch_all {
		return domain_ok(
			email,
			Reachable::Risky,
			"The domain accepts every address. Send it; the exact mailbox cannot be confirmed.",
		);
	}

	if signals.is_role_account {
		return response(
			email,
			Reachable::Risky,
			Some(true),
			true,
			Some(false),
			"mailbox",
			true,
			"The mailbox exists and will accept mail. It is a shared role address such as info@ or support@.",
		);
	}

	response(
		email,
		Reachable::Safe,
		Some(true),
		true,
		Some(false),
		"mailbox",
		true,
		"The mailbox exists. No message was sent, so this check cannot bounce.",
	)
}

fn has_smtp_proxy(config: &BackendConfig) -> bool {
	config.proxy.is_some() || !config.get_verif_method().proxies.is_empty()
}

async fn domain_signals(email: &str) -> Signals<'static> {
	let syntax = check_syntax(email);
	if !syntax.is_valid_syntax {
		return Signals {
			valid_syntax: false,
			accepts_mail: None,
			smtp_failed: true,
			smtp: None,
			is_disposable: false,
			is_role_account: false,
		};
	}

	let accepts_mail = match check_mx(&syntax).await {
		Err(_) => None,
		Ok(MxDetails { lookup }) => match lookup {
			Ok(records) => Some(records.iter().next().is_some()),
			Err(_) => Some(false),
		},
	};

	let misc = check_misc(&syntax, false, None).await;
	Signals {
		valid_syntax: true,
		accepts_mail,
		smtp_failed: true,
		smtp: None,
		is_disposable: misc.is_disposable,
		is_role_account: misc.is_role_account,
	}
}

async fn validate_email(
	config: Arc<BackendConfig>,
	email: String,
) -> Result<impl warp::Reply, warp::Rejection> {
	let email = email.trim().to_string();
	if email.is_empty() {
		return Err(ReacherResponseError::new(
			http::StatusCode::BAD_REQUEST,
			"email is required.",
		)
		.into());
	}

	let summary = if has_smtp_proxy(config.as_ref()) {
		let request = CheckEmailRequest {
			to_email: email,
			..CheckEmailRequest::default()
		};
		summarize(&check_email(&request.to_check_email_input(config)).await)
	} else {
		decide(&email, domain_signals(&email).await)
	};
	tracing::info!(
		target: LOG_TARGET,
		email = %summary.email,
		exists = ?summary.exists,
		safe_to_send = summary.safe_to_send,
		check_level = %summary.check_level,
		"Validated email"
	);
	Ok(warp::reply::json(&summary))
}

fn index() -> impl Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
	warp::path::end().and(warp::get()).map(|| {
		warp::reply::json(&serde_json::json!({
			"service": "email-validator",
			"message_sent": false,
			"usage": {
				"method": "POST",
				"path": "/validate",
				"body": {"email": "name@example.com"},
				"send_when": "safe_to_send is true"
			}
		}))
	})
}

fn health() -> impl Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
	warp::path!("health")
		.and(warp::get())
		.map(|| warp::reply::json(&serde_json::json!({"ok": true})))
}

/// `GET /validate?email=` and `POST /validate` with `{"email":"..."}`.
pub fn routes(
	config: Arc<BackendConfig>,
) -> impl Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
	let get_validate = warp::path!("validate")
		.and(warp::get())
		.and(check_header(Arc::clone(&config)))
		.and(with_config(Arc::clone(&config)))
		.and(warp::query::<ValidateQuery>())
		.and_then(|config, query: ValidateQuery| validate_email(config, query.email));

	let post_validate = warp::path!("validate")
		.and(warp::post())
		.and(check_header(config.clone()))
		.and(with_config(config))
		.and(warp::body::content_length_limit(1024 * 16))
		.and(warp::body::json())
		.and_then(|config, body: ValidateBody| {
			let email = body
				.email
				.or(body.to_email)
				.unwrap_or_default();
			validate_email(config, email)
		});

	index()
		.or(health())
		.or(get_validate)
		.or(post_validate)
		.with(warp::log(LOG_TARGET))
}

#[cfg(test)]
mod tests {
	use super::*;
	use check_if_email_exists::smtp::SmtpDetails;

	fn signals<'a>(smtp: Option<&'a SmtpDetails>, smtp_failed: bool) -> Signals<'a> {
		Signals {
			valid_syntax: true,
			accepts_mail: Some(true),
			smtp_failed,
			smtp,
			is_disposable: false,
			is_role_account: false,
		}
	}

	fn deliverable() -> SmtpDetails {
		SmtpDetails {
			can_connect_smtp: true,
			has_full_inbox: false,
			is_catch_all: false,
			is_deliverable: true,
			is_disabled: false,
		}
	}

	#[test]
	fn invalid_syntax_would_bounce() {
		let mut output = CheckEmailOutput::default();
		output.input = "not-an-email".into();
		let summary = summarize(&output);

		assert_eq!(summary.exists, Some(false));
		assert_eq!(summary.would_bounce, Some(true));
		assert!(!summary.safe_to_send);
		assert!(!summary.message_sent);
	}

	#[test]
	fn missing_mx_would_bounce() {
		let mut output = CheckEmailOutput::default();
		output.input = "person@example.com".into();
		output.syntax.is_valid_syntax = true;
		let summary = summarize(&output);

		assert_eq!(summary.exists, Some(false));
		assert_eq!(summary.would_bounce, Some(true));
		assert!(!summary.safe_to_send);
	}

	#[test]
	fn unreachable_smtp_is_safe_at_domain_level() {
		let summary = decide("person@example.com", signals(None, true));

		assert_eq!(summary.exists, None);
		assert_eq!(summary.would_bounce, Some(false));
		assert!(summary.safe_to_send);
		assert_eq!(summary.check_level, "domain");
		assert!(!summary.mailbox_confirmed);
		assert!(!summary.message_sent);
	}

	#[test]
	fn missing_mailbox_would_bounce() {
		let smtp = SmtpDetails {
			can_connect_smtp: true,
			is_deliverable: false,
			..SmtpDetails::default()
		};
		let summary = decide("person@example.com", signals(Some(&smtp), false));

		assert_eq!(summary.exists, Some(false));
		assert_eq!(summary.would_bounce, Some(true));
		assert!(!summary.safe_to_send);
	}

	#[test]
	fn existing_mailbox_is_safe_and_sends_nothing() {
		let smtp = deliverable();
		let summary = decide("person@example.com", signals(Some(&smtp), false));

		assert_eq!(summary.exists, Some(true));
		assert_eq!(summary.would_bounce, Some(false));
		assert!(summary.safe_to_send);
		assert!(!summary.message_sent);
	}

	#[test]
	fn full_inbox_exists_but_bounces() {
		let smtp = SmtpDetails {
			has_full_inbox: true,
			is_deliverable: false,
			..deliverable()
		};
		let summary = decide("person@example.com", signals(Some(&smtp), false));

		assert_eq!(summary.exists, Some(true));
		assert_eq!(summary.would_bounce, Some(true));
		assert!(!summary.safe_to_send);
	}
}
