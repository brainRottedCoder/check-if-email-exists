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
//! `/validate` reports whether a mailbox exists. The check stops after the
//! SMTP `RCPT TO` response, so no message is accepted and nothing can bounce.

use check_if_email_exists::misc::MiscDetails;
use check_if_email_exists::mx::MxDetails;
use check_if_email_exists::smtp::SmtpDetails;
use check_if_email_exists::{check_email, CheckEmailOutput, Reachable, LOG_TARGET};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use warp::{http, Filter};

use super::v0::check_email::post::{with_config, CheckEmailRequest};
use super::{check_header, ReacherResponseError};
use crate::config::BackendConfig;

/// Plain answer for "does this address exist, and would sending bounce?"
#[derive(Debug, PartialEq, Serialize)]
pub struct ValidateResponse {
	pub email: String,
	/// `true` when the mailbox exists, `false` when it does not, `null` when
	/// the mail server did not give a definite answer.
	pub exists: Option<bool>,
	/// Send only when this is `true`. That is the set of addresses that will
	/// not bounce.
	pub safe_to_send: bool,
	/// `true` when a real message would bounce, `false` when it would be
	/// accepted, `null` when that cannot be known.
	pub would_bounce: Option<bool>,
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
	reason: &str,
) -> ValidateResponse {
	ValidateResponse {
		email: email.to_string(),
		exists,
		safe_to_send,
		would_bounce,
		is_reachable: reachable_label(reachable).to_string(),
		message_sent: false,
		reason: reason.to_string(),
	}
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
				"The domain's mail server could not be looked up. No message was sent.",
			);
		}
		Some(false) => {
			return response(
				email,
				Reachable::Invalid,
				Some(false),
				false,
				Some(true),
				"The domain has no mail server, so a message to it would bounce.",
			);
		}
		Some(true) => {}
	}

	if signals.smtp_failed {
		return response(
			email,
			Reachable::Unknown,
			None,
			false,
			None,
			"The mail server did not answer, so the mailbox could not be confirmed. No message was sent. On Render this usually means outbound port 25 is blocked; set a SOCKS5 proxy to finish the check.",
		);
	}

	let smtp = match signals.smtp {
		Some(details) => details,
		None => {
			return response(
				email,
				Reachable::Unknown,
				None,
				false,
				None,
				"The mail server did not answer, so the mailbox could not be confirmed. No message was sent.",
			);
		}
	};

	if !smtp.can_connect_smtp {
		return response(
			email,
			Reachable::Unknown,
			None,
			false,
			None,
			"Could not connect to the mail server. No message was sent. On Render, outbound port 25 is blocked, so set a SOCKS5 proxy to confirm the mailbox.",
		);
	}

	if smtp.is_disabled || (!smtp.is_deliverable && !smtp.is_catch_all && !smtp.has_full_inbox) {
		return response(
			email,
			Reachable::Invalid,
			Some(false),
			false,
			Some(true),
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
			"The mailbox exists, but the inbox is full, so a message would bounce.",
		);
	}

	if smtp.is_catch_all {
		return response(
			email,
			Reachable::Risky,
			None,
			false,
			None,
			"The domain accepts every address, so this exact mailbox cannot be confirmed. Sending may bounce.",
		);
	}

	if signals.is_disposable {
		return response(
			email,
			Reachable::Risky,
			Some(true),
			false,
			None,
			"The mailbox exists, but it is a disposable address and later mail to it often bounces.",
		);
	}

	if signals.is_role_account {
		return response(
			email,
			Reachable::Risky,
			Some(true),
			true,
			Some(false),
			"The mailbox exists and will accept mail. It is a shared role address such as info@ or support@.",
		);
	}

	response(
		email,
		Reachable::Safe,
		Some(true),
		true,
		Some(false),
		"The mailbox exists. No message was sent, so this check cannot bounce.",
	)
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

	let request = CheckEmailRequest {
		to_email: email,
		..CheckEmailRequest::default()
	};
	let output = check_email(&request.to_check_email_input(config)).await;
	let summary = summarize(&output);
	tracing::info!(
		target: LOG_TARGET,
		email = %summary.email,
		exists = ?summary.exists,
		safe_to_send = summary.safe_to_send,
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
				"body": {"email": "name@example.com"}
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
	fn unreachable_smtp_is_unknown() {
		let summary = decide("person@example.com", signals(None, true));

		assert_eq!(summary.exists, None);
		assert_eq!(summary.would_bounce, None);
		assert!(!summary.safe_to_send);
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
