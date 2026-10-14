import { Effect, Layer } from "effect";
import { ApiKeys } from "./api-keys/api-keys.ts";
import { Clients } from "./clients/clients.ts";
import { Issuer } from "./issuer/issuer.ts";
import { Settings } from "./issuer/settings.ts";
import { OwnerAccount } from "./owner/owner.ts";
import { CimdTransport } from "./platform/cimd-transport.ts";
import { Database } from "./platform/sqlite.ts";
import { ResourceCatalog } from "./resources/catalog.ts";
import { Resources } from "./resources/resources.ts";

/**
 * Every service the issuer runs on, from the settings and CIMD transport an entry chooses.
 * Building it opens the database, migrates and initializes the provider, and publishes the
 * resource catalog; closing its scope closes the database last.
 */
export const issuerServices = <E>(
  settings: Layer.Layer<Settings, E>,
  cimdTransport: Layer.Layer<CimdTransport>,
) => {
  const database = Layer.unwrap(Effect.map(Settings, ({ database }) => Database.layer(database)));

  return Layer.mergeAll(OwnerAccount.layer, Clients.layer, ApiKeys.layer).pipe(
    Layer.provideMerge(Resources.layer),
    Layer.provideMerge(Issuer.layer),
    Layer.provideMerge(ResourceCatalog.layer),
    Layer.provideMerge(database),
    Layer.provideMerge(Layer.merge(settings, cimdTransport)),
  );
};

export type IssuerServices = Layer.Success<ReturnType<typeof issuerServices>>;
