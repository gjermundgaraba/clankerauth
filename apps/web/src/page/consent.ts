import { Array, Effect, Option, Schema, String, pipe } from "effect";
import { Command } from "foldkit";
import type { Html, HtmlBuilder } from "foldkit/html";
import { defineMessageUnion } from "foldkit/message";
import { defineTaggedUnion } from "foldkit/schema";
import { modifyFields } from "foldkit/struct";
import { defineView } from "foldkit/submodel";
import type * as Update from "foldkit/update";
import {
  Button,
  CodeSurface,
  Disclosure,
  Identity,
  Loading,
  Notice,
  Outcome,
  PropsList,
  Rows,
} from "@gjermundgaraba-designs/pixel-paper";

import { decideConsent, publicClientName } from "../api.ts";
import { wallCardView } from "./wall.ts";

// MODEL

/** What a signed authorization request asks, as the provider wrote it into this page's query. */
const ConsentRequest = Schema.Struct({
  clientId: Schema.String,
  scopes: Schema.Array(Schema.String),
  resources: Schema.Array(Schema.String),
  maybeRedirect: Schema.Option(Schema.String),
  maybeClaims: Schema.Option(Schema.String),
});

type ConsentRequest = typeof ConsentRequest.Type;

const Decision = Schema.Literals(["Undecided", "Allowing", "Denying"]);

type Decision = typeof Decision.Type;

/** The page stops on an incomplete request or a client it cannot name, waits for the client's
 *  name, and then asks. */
export const Model = defineTaggedUnion({
  Stopped: { reason: Schema.String },
  Loading: { request: ConsentRequest },
  Asking: {
    request: ConsentRequest,
    maybeName: Schema.Option(Schema.String),
    granted: Schema.Array(Schema.String),
    decision: Decision,
    maybeRefusal: Schema.Option(Schema.String),
    isClaimsOpen: Schema.Boolean,
  },
});

export type Model = typeof Model.Type;

type Asking = typeof Model.Asking.Type;

type UpdateReturn = Update.Return<Model, Message>;

// MESSAGE

export const Message = defineMessageUnion({
  SucceededFetchClientName: { maybeName: Schema.Option(Schema.String) },
  FailedFetchClientName: { reason: Schema.String },
  ToggledScope: { scope: Schema.String, isChecked: Schema.Boolean },
  ToggledClaims: { isOpen: Schema.Boolean },
  ClickedAllow: {},
  ClickedDeny: {},
  SucceededDecideConsent: {},
  FailedDecideConsent: { reason: Schema.String },
});

export type Message = typeof Message.Type;

// COMMAND

export const FetchClientName = Command.define("FetchClientName", {
  args: { clientId: Schema.String },
  messages: [Message.SucceededFetchClientName, Message.FailedFetchClientName],
  execute: ({ clientId }) =>
    publicClientName(clientId).pipe(
      Effect.match({
        onFailure: (reason) => Message.FailedFetchClientName({ reason }),
        onSuccess: (maybeName) => Message.SucceededFetchClientName({ maybeName }),
      }),
    ),
});

export const DecideConsent = Command.define("DecideConsent", {
  args: { accept: Schema.Boolean, maybeScope: Schema.Option(Schema.String) },
  messages: [Message.SucceededDecideConsent, Message.FailedDecideConsent],
  execute: ({ accept, maybeScope }) =>
    decideConsent(accept, maybeScope).pipe(
      Effect.match({
        onFailure: (reason) => Message.FailedDecideConsent({ reason }),
        onSuccess: () => Message.SucceededDecideConsent(),
      }),
    ),
});

// INIT

const INCOMPLETE = "Start authorization from your application; this consent link is incomplete.";

/** The request the provider signed into the query, or none when the link is incomplete. */
const requestOf = (search: string): Option.Option<ConsentRequest> => {
  const query = new URLSearchParams(search);

  return pipe(
    Option.fromNullishOr(query.get("client_id")),
    Option.filter(String.isNonEmpty),
    Option.filter(() => query.has("sig")),
    Option.map((clientId) => ({
      clientId,
      scopes: pipe(query.get("scope") ?? "", String.split(" "), Array.filter(String.isNonEmpty)),
      resources: query.getAll("resource"),
      maybeRedirect: Option.fromNullishOr(query.get("redirect_uri")),
      maybeClaims: Option.fromNullishOr(query.get("claims")),
    })),
  );
};

/** The consent page for the address's query, fetching the asking client's name when the
 *  request is one the provider signed. */
export const init = (search: string): UpdateReturn =>
  Option.match(requestOf(search), {
    onNone: () => ({ model: Model.Stopped({ reason: INCOMPLETE }) }),
    onSome: (request) => ({
      model: Model.Loading({ request }),
      commands: [FetchClientName({ clientId: request.clientId })],
    }),
  });

// UPDATE

const NOTHING_GRANTED = "Tick at least one permission, or deny the request.";

/** Applies a step to a page that is asking, and leaves any other page as it is. */
const whileAsking = (model: Model, step: (asking: Asking) => UpdateReturn): UpdateReturn =>
  Model.matchOrElse(model, { Asking: step }, () => ({ model }));

const decided = (
  asking: Asking,
  decision: Exclude<Decision, "Undecided">,
  maybeScope: Option.Option<string>,
): UpdateReturn => ({
  model: modifyFields(asking, {
    decision: () => decision,
    maybeRefusal: () => Option.none(),
  }),
  commands: [DecideConsent({ accept: decision === "Allowing", maybeScope })],
});

// The provider refuses an empty scope, and leaving the scope out approves what was requested.
const allowed = (asking: Asking): UpdateReturn =>
  Array.match(asking.granted, {
    onEmpty: () =>
      Array.match(asking.request.scopes, {
        onEmpty: () => decided(asking, "Allowing", Option.none()),
        onNonEmpty: () => ({
          model: modifyFields(asking, { maybeRefusal: () => Option.some(NOTHING_GRANTED) }),
        }),
      }),
    onNonEmpty: (granted) => decided(asking, "Allowing", Option.some(Array.join(granted, " "))),
  });

const whenUndecided = (asking: Asking, step: (asking: Asking) => UpdateReturn): UpdateReturn =>
  asking.decision === "Undecided" ? step(asking) : { model: asking };

export const update = (model: Model, message: Message) =>
  Message.match<UpdateReturn>(message, {
    SucceededFetchClientName: ({ maybeName }) =>
      Model.matchOrElse<UpdateReturn>(
        model,
        {
          Loading: ({ request }) => ({
            model: Model.Asking({
              request,
              maybeName,
              granted: request.scopes,
              decision: "Undecided",
              maybeRefusal: Option.none(),
              isClaimsOpen: false,
            }),
          }),
        },
        () => ({ model }),
      ),
    FailedFetchClientName: ({ reason }) => ({ model: Model.Stopped({ reason }) }),
    ToggledScope: ({ scope, isChecked }) =>
      whileAsking(model, (asking) => ({
        model: modifyFields(asking, {
          granted: (granted) =>
            Array.filter(asking.request.scopes, (requested) =>
              requested === scope ? isChecked : Array.contains(granted, requested),
            ),
        }),
      })),
    ToggledClaims: ({ isOpen }) =>
      whileAsking(model, (asking) => ({
        model: modifyFields(asking, { isClaimsOpen: () => isOpen }),
      })),
    ClickedAllow: () => whileAsking(model, (asking) => whenUndecided(asking, allowed)),
    ClickedDeny: () =>
      whileAsking(model, (asking) =>
        whenUndecided(asking, (undecided) => decided(undecided, "Denying", Option.none())),
      ),
    // NOTE: the provider client follows the redirect to the client's callback itself, and a
    // second navigation would cancel it, so the decision stays in force until the page goes.
    SucceededDecideConsent: () => ({ model }),
    FailedDecideConsent: ({ reason }) =>
      whileAsking(model, (asking) => ({
        model: modifyFields(asking, {
          decision: () => "Undecided",
          maybeRefusal: () => Option.some(reason),
        }),
      })),
  });

// VIEW

const HEADING = "Allow this connection?";

/** A client identified by its metadata document's https address names the host it lives on,
 *  which the client cannot choose the way it chooses its display name. */
const metadataHostOf = (clientId: string): Option.Option<string> =>
  pipe(
    clientId,
    Option.liftPredicate((id) => URL.canParse(id)),
    Option.map((id) => new URL(id)),
    Option.filter(({ protocol }) => protocol === "https:"),
    Option.map(({ hostname }) => hostname),
  );

const stoppedView = (reason: string, h: HtmlBuilder<Message>): Html =>
  wallCardView(
    HEADING,
    {
      title: "Allow access",
      meta: "not available",
      body: [Outcome.view({ tone: "Error", title: "Unable to continue", body: [reason] }, h)],
    },
    h,
  );

const loadingView = (h: HtmlBuilder<Message>): Html =>
  wallCardView(
    HEADING,
    {
      title: "Allow access",
      body: [Loading.view({ isLoading: true, label: "reading the request" }, h)],
    },
    h,
  );

const codesView = (
  values: ReadonlyArray<string>,
  h: HtmlBuilder<Message>,
): ReadonlyArray<Html | string> =>
  Array.match(values, {
    onEmpty: () => ["None in this request"],
    onNonEmpty: (present) => Array.map(present, (value) => h.code([], [value])),
  });

const scopesView = (asking: Asking, h: HtmlBuilder<Message>): Html =>
  Array.match(asking.request.scopes, {
    onEmpty: () => h.p([h.Class("note-line")], ["No permissions requested beyond signing in."]),
    onNonEmpty: (scopes) =>
      Rows.view(
        {
          label: "Requested access",
          rows: Array.map(scopes, (scope) =>
            Rows.rowView(
              {
                key: scope,
                body: [h.code([], [scope])],
                select: {
                  id: `consent-scope-${scope}`,
                  isChecked: Array.contains(asking.granted, scope),
                  onToggle: (isChecked) => Message.ToggledScope({ scope, isChecked }),
                },
              },
              h,
            ),
          ),
        },
        h,
      ),
  });

const decisionActionsView = (asking: Asking, h: HtmlBuilder<Message>): ReadonlyArray<Html> => [
  Button.view(
    {
      label: "deny",
      onClick: Message.ClickedDeny(),
      isBusy: asking.decision === "Denying",
      isDisabled: asking.decision === "Allowing",
    },
    h,
  ),
  Button.view(
    {
      label: "allow access",
      variant: "Primary",
      isDefault: true,
      onClick: Message.ClickedAllow(),
      isBusy: asking.decision === "Allowing",
      isDisabled: asking.decision === "Denying",
    },
    h,
  ),
];

/** Who asks and where the answer goes, in the provider's words rather than the client's. */
const requestDetailsView = (
  { clientId, maybeRedirect, resources }: ConsentRequest,
  name: string,
  h: HtmlBuilder<Message>,
): ReadonlyArray<Html> => [
  Identity.view({ label: name, isLarge: true, meta: [h.code([], [clientId])] }, h),
  h.p([], [h.strong([], [name]), " wants to act on your behalf."]),
  ...Option.toArray(
    Option.map(metadataHostOf(clientId), (host) =>
      h.p([], ["Client metadata host: ", h.strong([], [host])]),
    ),
  ),
  PropsList.view(
    {
      items: [
        { label: "client id", value: [clientId], isCode: true },
        {
          label: "callback",
          value: Option.match(maybeRedirect, {
            onNone: () => ["Not supplied in this request"],
            onSome: (redirect) => [h.code([], [redirect])],
          }),
        },
        { label: "only for", value: codesView(resources, h) },
      ],
    },
    h,
  ),
  h.p(
    [h.Class("note-line")],
    ["The client supplies its display name. Review the identifier and callback before approving."],
  ),
];

const claimsView = (asking: Asking, h: HtmlBuilder<Message>): ReadonlyArray<Html> =>
  Option.toArray(
    Option.map(asking.request.maybeClaims, (claims) =>
      Disclosure.view(
        {
          id: "consent-claims",
          label: "additional identity claims",
          isOpen: asking.isClaimsOpen,
          onToggle: (isOpen) => Message.ToggledClaims({ isOpen }),
          body: [CodeSurface.view({ label: "Requested claims", body: [claims] }, h)],
        },
        h,
      ),
    ),
  );

const refusalView = (asking: Asking, h: HtmlBuilder<Message>): ReadonlyArray<Html> =>
  Option.toArray(
    Option.map(asking.maybeRefusal, (reason) =>
      Notice.view({ tone: "Error", title: "Not answered", body: [reason] }, h),
    ),
  );

const askingView = (asking: Asking, h: HtmlBuilder<Message>): Html =>
  wallCardView(
    HEADING,
    {
      title: "Allow access",
      meta: "permission request",
      isNarrow: false,
      actions: decisionActionsView(asking, h),
      body: [
        ...requestDetailsView(
          asking.request,
          Option.getOrElse(asking.maybeName, () => asking.request.clientId),
          h,
        ),
        scopesView(asking, h),
        h.p(
          [h.Class("note-line")],
          [
            "Untick anything this Client should not get. It receives only what stays ticked. Access tokens expire after fifteen minutes; offline access lets the Client renew them until you revoke its authorization.",
          ],
        ),
        ...claimsView(asking, h),
        ...refusalView(asking, h),
      ],
    },
    h,
  );

export const view = defineView<Model, Message>((model, h): Html =>
  Model.match(model, {
    Stopped: ({ reason }) => stoppedView(reason, h),
    Loading: () => loadingView(h),
    Asking: (asking) => askingView(asking, h),
  }),
);
