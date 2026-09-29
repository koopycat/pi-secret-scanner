/**
 * Named regex patterns for well-known secret formats.
 *
 * Each pattern has:
 *   name        - display label shown in warnings
 *   regex       - detection pattern (global flag required for scanText)
 *   confidence  - "high" (format is very specific) | "medium" (may have false positives)
 */

export interface SecretPattern {
	name: string;
	regex: RegExp;
	/** Capture group containing only the secret. Omit to redact the full match. */
	secretGroup?: number;
	/** Return true to skip this match -- used for language-aware FP suppression. */
	rejectValue?: (value: string) => boolean;
	confidence: "high" | "medium";
}

const SOURCE_REFERENCE = /^[A-Za-z_$][A-Za-z0-9_$]*(?:(?:\?\.|\.)[A-Za-z_$][A-Za-z0-9_$]*)*$/;
const SOURCE_EXPRESSION_PREFIX =
	/^(?:`)?[A-Za-z_$][A-Za-z0-9_$]*(?:(?:\?\.|\.)[A-Za-z_$][A-Za-z0-9_$]*)*(?:\(|\?\?|&&|\|\||=\$\{)/;
const MASKED_SECRET = /^[A-Za-z0-9_-]*\*{4,}$/;

export const SECRET_PATTERNS: SecretPattern[] = [
	// ── PEM private keys ──────────────────────────────────────────────────────
	{
		name: "Private Key (PEM)",
		// Require real or escaped newlines around the body. This avoids matching
		// arrays of source-code string fragments that merely spell both markers.
		regex: /-----BEGIN\s(?:RSA |EC |DSA |OPENSSH |)?PRIVATE KEY-----(?:\r?\n|\\r?\\n)[A-Za-z0-9+/=\s\\]+?(?:\r?\n|\\r?\\n)-----END\s(?:RSA |EC |DSA |OPENSSH |)?PRIVATE KEY-----/g,
		confidence: "high",
	},

	// ── AWS ──────────────────────────────────────────────────────────────────
	{
		name: "AWS Access Key ID",
		regex: /(?<![A-Z0-9])(?:AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])/g,
		confidence: "high",
	},
	{
		name: "AWS Secret Access Key",
		// 40-char base62+/+ immediately after common env-var / config prefixes
		regex: /(?:aws[_\-.]?secret[_\-.]?(?:access[_\-.]?)?key|AWS_SECRET_ACCESS_KEY)\s*[=:]\s*["']?([A-Za-z0-9/+=]{40})["']?/gi,
		secretGroup: 1,
		confidence: "high",
	},

	// ── GitHub ────────────────────────────────────────────────────────────────
	{
		name: "GitHub Personal Access Token (classic)",
		regex: /ghp_[A-Za-z0-9]{36}/g,
		confidence: "high",
	},
	{
		name: "GitHub OAuth Token",
		regex: /gho_[A-Za-z0-9]{36}/g,
		confidence: "high",
	},
	{
		name: "GitHub App Token",
		regex: /(?:ghu|ghs)_[A-Za-z0-9]{36}/g,
		confidence: "high",
	},
	{
		name: "GitHub Fine-Grained PAT",
		regex: /github_pat_[A-Za-z0-9_]{82}/g,
		confidence: "high",
	},

	// ── Google ────────────────────────────────────────────────────────────────
	{
		name: "Google API Key",
		regex: /AIza[0-9A-Za-z\-_]{35}/g,
		confidence: "high",
	},
	{
		name: "Google OAuth Client Secret",
		regex: /GOCSPX-[A-Za-z0-9\-_]{28}/g,
		confidence: "high",
	},

	// ── Stripe ────────────────────────────────────────────────────────────────
	{
		name: "Stripe Live Secret Key",
		regex: /sk_live_[0-9a-zA-Z]{24,}/g,
		confidence: "high",
	},
	{
		name: "Stripe Test Secret Key",
		regex: /sk_test_[0-9a-zA-Z]{24,}/g,
		confidence: "high",
	},

	// ── Slack ─────────────────────────────────────────────────────────────────
	{
		name: "Slack Bot/User Token",
		regex: /xox[baprs]-(?:[0-9]{10,12}-){1,3}[a-zA-Z0-9]{10,}/g,
		confidence: "high",
	},
	{
		name: "Slack Webhook URL",
		regex: /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[A-Za-z0-9]+/g,
		confidence: "high",
	},

	// ── Twilio ────────────────────────────────────────────────────────────────
	{
		// Require context prefix to avoid false positives on git SHAs and other hex strings
		name: "Twilio Account SID",
		regex: /(?:twilio[_\-.]?(?:account[_\-.]?)?sid|TWILIO_ACCOUNT_SID)\s*[=:]\s*["']?(AC[a-f0-9]{32})["']?/gi,
		secretGroup: 1,
		confidence: "high",
	},
	{
		name: "Twilio Auth Token",
		regex: /(?:twilio[_\-.]?auth[_\-.]?token|TWILIO_AUTH_TOKEN)\s*[=:]\s*["']?([a-f0-9]{32})["']?/gi,
		secretGroup: 1,
		confidence: "high",
	},

	// ── NPM ───────────────────────────────────────────────────────────────────
	{
		name: "NPM Access Token",
		regex: /npm_[A-Za-z0-9]{36}/g,
		confidence: "high",
	},

	// ── Telegram ──────────────────────────────────────────────────────────────
	{
		name: "Telegram Bot Token",
		regex: /[0-9]{8,10}:[A-Za-z0-9_\-]{35}/g,
		confidence: "medium",
	},

	// ── SendGrid ──────────────────────────────────────────────────────────────
	{
		name: "SendGrid API Key",
		regex: /SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}/g,
		confidence: "high",
	},

	// ── Mailchimp ─────────────────────────────────────────────────────────────
	{
		name: "Mailchimp API Key",
		regex: /[a-f0-9]{32}-us[0-9]{1,2}/g,
		confidence: "medium",
	},

	// ── Heroku ────────────────────────────────────────────────────────────────
	{
		name: "Heroku API Key",
		regex: /(?:heroku[_\-.]?(?:api[_\-.]?)?key|HEROKU_API_KEY)\s*[=:]\s*["']?([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})["']?/gi,
		secretGroup: 1,
		confidence: "high",
	},

	// ── Databricks ────────────────────────────────────────────────────────────
	{
		name: "Databricks Token",
		regex: /dapi[a-f0-9]{32}/g,
		confidence: "high",
	},

	// ── OpenAI ────────────────────────────────────────────────────────────────
	{
		name: "OpenAI API Key",
		// Negative lookahead (?![A-Za-z0-9]) prevents partial match on longer keys
		regex: /sk-[A-Za-z0-9]{48}(?:T3BlbkFJ[A-Za-z0-9]{48})?(?![A-Za-z0-9])/g,
		confidence: "high",
	},
	{
		name: "OpenAI Project/Service Key",
		regex: /sk-(?:proj|svcacct)-[A-Za-z0-9_\-]{50,}/g,
		confidence: "high",
	},

	// ── Anthropic ─────────────────────────────────────────────────────────────
	{
		name: "Anthropic API Key",
		regex: /sk-ant-(?:api03-)?[A-Za-z0-9_\-]{93,}/g,
		confidence: "high",
	},

	// ── JWT ───────────────────────────────────────────────────────────────────
	{
		name: "JSON Web Token",
		regex: /eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+/g,
		confidence: "medium",
	},

	// ── Generic password assignments ──────────────────────────────────────────
	// Catches: PASSWORD=abc123, "password": "s3cr3t", etc.
	//
	// secretGroup 1: only the value is redacted; the assignment itself and all
	// surrounding code stay visible to the agent.
	//
	// Values shaped like source code are rejected via `rejectValue` (kept out of
	// the regex because the `i` flag folds [A-Z] onto lowercase, making case
	// detection inside the pattern impossible):
	//   - dotted / optional-chained references (process.env.FOO, opts?.apiKey)
	//   - nullish/logical source expressions and function calls
	//   - bare camelCase/PascalCase identifiers (apiKey: kiloToken)
	// All-lowercase identifier values (password=hunter2) and hyphenated literals
	// (apiKey: literal-api-key-value) are still detected.
	{
		name: "Generic Password Assignment",
		regex: /(?:^|[\s,;{[(])(?:password|passwd|pwd|secret|token|api[_\-.]?key|auth[_\-.]?key|auth[_\-.]?token|access[_\-.]?token|private[_\-.]?key)\s*[=:]\s*["']?(?!\s*(?:true|false|null|undefined|\$\{|\{\{|<[A-Z_]+>|your[_\-]|xxx|123|test|example|placeholder|changeme|replace))([^\s"',;\]})]{8,})["']?/gim,
		secretGroup: 1,
		confidence: "medium",
		rejectValue: (value) =>
			// Dotted / optional-chained references: process.env.FOO, opts?.apiKey.
			SOURCE_REFERENCE.test(value) ||
			// Truncated source expressions: the assignment matcher stops at whitespace
			// and quotes, so calls and nullish/logical expressions end here.
			SOURCE_EXPRESSION_PREFIX.test(value) ||
			// Masked values printed by CLIs are evidence that a secret was withheld,
			// not credentials that can leak to a provider.
			MASKED_SECRET.test(value) ||
			// Bare camelCase/PascalCase identifiers: local variables, object props.
			/^[A-Za-z_$][A-Za-z0-9_$]*[A-Z][A-Za-z0-9_$]*$/.test(value),
	},

	// ── URLs with embedded credentials ────────────────────────────────────────
	{
		name: "URL with Embedded Credentials",
		regex: /[a-zA-Z][a-zA-Z0-9+\-.]*:\/\/[^@\s"'`]+:[^@\s"'`]{3,}@[^\s"'`]+/g,
		confidence: "high",
	},
];
