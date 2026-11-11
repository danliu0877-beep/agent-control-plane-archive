# Security boundaries

ACP is a discontinued, single-user local experiment. There are no supported production versions or promised security updates.

The board binds to loopback and checks Host/Origin/CSRF state. This is not multi-user authentication. Actor labels are audit attribution, not identity proof. Do not reverse-proxy, tunnel or expose the board to a network.

Keep runtime state outside every Git checkout, restrict access yourself, and use disposable synthetic project data. Do not import production databases, account credentials or private business material. Source sanitization and pattern scanning do not prove that software is secure.

The optional OpenAI Responses transport omits HTTP-error bodies, reasons and headers before durable storage, retaining only a bounded numeric status and an omission marker. Request-setup/transport exceptions expose a fixed error without the original exception chain; uncertain delivery still cannot trigger automatic reinvocation. Ordinary response bytes remain exact audit receipts unless they contain the active API key literally or in the standard JSON-escaped form, in which case the body is omitted and rejected. These are narrow reflection protections, not a general secret scanner: other secrets, partial/encoded reflections, caller-supplied inputs and custom/submitted providers are outside this fix. Existing databases are not rewritten. Do not put sensitive data in this experiment.

The optional VMware path requires a separately validated disposable lab. Its guest password can appear in vmrun process arguments. Use a dedicated disposable guest credential, never a production or reused password. Included fixtures and scripts are not a transferable certification for a new machine or changed source.

Some historical isolation approaches failed. Real-world autonomous execution and live providers are not certified by the M12 snapshot. Never weaken a gate to make a demo pass.

If you discover a possible credential or private-data exposure, do not reproduce the value in a public issue. Use a private reporting channel if the repository owner has enabled one. No monitored private channel or response time is currently promised.
