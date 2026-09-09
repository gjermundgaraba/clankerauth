import { readFileSync } from "node:fs";
import { Effect } from "effect";
import { hashPassword } from "better-auth/crypto";
import { loadSettings } from "./config.ts";
import { migrate, openAuth, type Service } from "./auth.ts";

export async function bootstrapOwner(service: Service, email: string, password: string) {
  if (service.db.prepare("SELECT id FROM user LIMIT 1").get() || service.owner())
    throw new Error("Bootstrap refused: accounts already exist");
  const result = await service.auth.api.signUpEmail({ body: { email, password, name: "Owner" } });
  service.db.prepare("INSERT INTO serviceOwner (id, userId) VALUES (1, ?)").run(result.user.id);
  service.db.prepare("DELETE FROM session").run();
}

export async function recoverOwner(service: Service, password: string) {
  const id = service.owner();
  if (!id) throw new Error("No owner to recover");
  if (password.length < 16 || password.length > 128)
    throw new Error("Password must be 16–128 characters");
  const hash = await hashPassword(password);
  // Offline emergency operation, intentionally invalidates all grants, not only browser sessions.
  service.db.transaction(() => {
    const updated = service.db
      .prepare(
        "UPDATE account SET password = ?, updatedAt = ? WHERE userId = ? AND providerId = 'credential'",
      )
      .run(hash, Date.now(), id);
    if (updated.changes !== 1) throw new Error("Owner credential missing");
    for (const table of [
      "oauthAccessToken",
      "oauthRefreshToken",
      "oauthConsent",
      "verification",
      "session",
    ]) {
      service.db.prepare(`DELETE FROM ${table}`).run();
    }
  })();
}

if (import.meta.main) {
  process.umask(0o077);
  const program = Effect.gen(function* () {
    const settings = yield* loadSettings;
    const command = process.argv[2];
    const service = openAuth(settings, command === "bootstrap");
    try {
      yield* Effect.tryPromise(async () => {
        if (command === "migrate") await migrate(service);
        else if (command === "bootstrap" || command === "recover") {
          if (process.stdin.isTTY)
            throw new Error(
              "Read password from stdin, e.g. a password-manager pipe; never command arguments",
            );
          const password = readFileSync(0, "utf8").replace(/\r?\n$/, "");
          if (command === "bootstrap") {
            const email = process.argv[3];
            if (!email)
              throw new Error(
                "Usage: pnpm auth:admin bootstrap owner@example.internal < password-file",
              );
            await bootstrapOwner(service, email, password);
          } else await recoverOwner(service, password);
        } else throw new Error("Usage: pnpm auth:admin migrate | bootstrap <email> | recover");
      });
      console.log("Owner administration completed.");
    } finally {
      service.db.close();
    }
  });
  await Effect.runPromise(program).catch(() => {
    console.error(
      "Administration failed. Check configuration, migration state and command prerequisites; no secrets logged.",
    );
    process.exitCode = 1;
  });
}
