/**
 * Deterministic fake OpenAI-compatible chat-completions provider for CI.
 *
 * Scripts a two-turn conversation so the smoke test exercises both scanner
 * hooks without needing a real LLM:
 *
 *   turn 1: respond with a `read` tool call for the planted-secret file
 *           -> exercises the tool_result redaction hook
 *   turn 2: respond with final text "SMOKE_OK"
 *
 * pi sends `stream: true`, so responses are emitted as SSE chunks.
 * Records every request body so run.mjs can assert redaction happened
 * in-flight (before the payload left for the "provider").
 */
import http from "node:http";

/**
 * @param {string} secretFilePath absolute path handed to the `read` tool call
 * @returns {{ close(): void, port: number, requests: Array<{ path: string, body: any, raw: string }> }}
 */
export function startFakeProvider(secretFilePath) {
	/** @type {Array<{ path: string, body: any, raw: string }>} */
	const requests = [];

	let id = 0;
	function sse(res, delta, finishReason) {
		id += 1;
		const chunk = {
			id: "chatcmpl-smoke",
			object: "chat.completion.chunk",
			created: Math.floor(Date.now() / 1000),
			model: "smoke-model",
			choices: [{ index: 0, delta, finish_reason: finishReason }],
		};
		res.write(`data: ${JSON.stringify(chunk)}\n\n`);
	}

	const server = http.createServer((req, res) => {
		let raw = "";
		req.on("data", (chunk) => {
			raw += chunk;
		});
		req.on("end", () => {
			let body = {};
			try {
				body = JSON.parse(raw);
			} catch {
				// Malformed body: record and keep going, assertions will fail later.
			}
			requests.push({ path: req.url, body, raw });

			res.writeHead(200, {
				"content-type": "text/event-stream",
				"cache-control": "no-cache",
				connection: "keep-alive",
			});

			if (requests.length === 1) {
				// Turn 1: request a read of the planted-secret file.
				sse(
					res,
					{
						role: "assistant",
						content: null,
						tool_calls: [
							{
								index: 0,
								id: "call_smoke_1",
								type: "function",
								function: {
									name: "read",
									arguments: JSON.stringify({ path: secretFilePath }),
								},
							},
						],
					},
					null,
				);
				sse(res, {}, "tool_calls");
			} else {
				// Turn 2: finish the conversation.
				sse(res, { role: "assistant", content: "SMOKE_OK" }, null);
				sse(res, {}, "stop");
			}
			res.write("data: [DONE]\n\n");
			res.end();
		});
	});

	const port = 18000 + Math.floor(Math.random() * 2000);
	server.listen(port, "127.0.0.1");

	return {
		requests,
		get port() {
			return /** @type {import("node:net").AddressInfo} */ (server.address()).port;
		},
		close() {
			server.close();
		},
	};
}
