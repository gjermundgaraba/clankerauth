import { Array, Match, Option } from "effect";
import { AsyncData } from "foldkit";
import type { Html, HtmlBuilder } from "foldkit/html";
import { defineView } from "foldkit/submodel";
import {
  Announcer,
  Button,
  Card,
  ConfirmDialog,
  CopyButton,
  Deck,
  Dialog,
  IconButton,
  LinkButton,
  Loading,
  NavStrip,
  Notice,
  Outcome,
  Panel,
  PropsList,
  Secret,
  TopBar,
  Wordmark,
} from "@gjermundgaraba-designs/pixel-paper";

import { PRODUCT, wallCardView } from "../wall.ts";
import {
  AppRoute,
  type DashboardRoute,
  clientsRouter,
  keysRouter,
  loginRouter,
  resourcesRouter,
} from "../../route.ts";
import { Credential, credentialId } from "./change.ts";
import { clientsHeadView, clientsPanels } from "./clients.ts";
import { NOT_REFRESHED, REFUSAL_ID } from "./constant.ts";
import * as Form from "./form.ts";
import * as FormView from "./formView.ts";
import { grantableResources, keysHeadView, keysPanels } from "./keys.ts";
import type { Listing } from "./listing.ts";
import { Message } from "./message.ts";
import {
  Activity,
  type Model,
  type PendingCredential,
  isHeld,
  isSaving,
  listingOf,
  pendingConfirmation,
  refusalAt,
} from "./model.ts";
import type { SectionContext } from "./parts.ts";
import { resourcesHeadView, resourcesPanels } from "./resources.ts";

/** Which of the dashboard's screens is on show; the application's route decides. */
export type ViewInputs = Readonly<{ section: DashboardRoute }>;

// WAITING

const waitingView = (h: HtmlBuilder<Message>): Html =>
  Deck.view(
    {
      body: [
        h.h1([h.Class("sr-only")], ["Dashboard"]),
        Loading.view({ isLoading: true, label: "loading the dashboard" }, h),
      ],
    },
    h,
  );

const unavailableView = (reason: string, h: HtmlBuilder<Message>): Html =>
  wallCardView(
    "Unable to continue",
    {
      title: "Dashboard",
      meta: "not available",
      actions: [
        LinkButton.view({ label: "sign in", href: loginRouter() }, h),
        Button.view(
          {
            label: "try again",
            variant: "Primary",
            isDefault: true,
            onClick: Message.ClickedRetryListing(),
          },
          h,
        ),
      ],
      body: [Outcome.view({ tone: "Error", title: "Unable to continue", body: [reason] }, h)],
    },
    h,
  );

// CONSOLE

const topBarView = (
  model: Model,
  listing: Listing,
  section: DashboardRoute,
  h: HtmlBuilder<Message>,
): Html =>
  TopBar.view(
    {
      brand: [Wordmark.view({ label: PRODUCT, href: clientsRouter() }, h)],
      nav: [
        NavStrip.view(
          {
            label: "Dashboard",
            items: [
              {
                href: clientsRouter(),
                label: "clients",
                count: listing.overview.clients.length,
                isCurrent: AppRoute.guards.Clients(section),
              },
              {
                href: resourcesRouter(),
                label: "resources",
                count: listing.overview.resources.length,
                isCurrent: AppRoute.guards.Resources(section),
              },
              {
                href: keysRouter(),
                label: "api keys",
                count: listing.keys.length,
                isCurrent: AppRoute.guards.Keys(section),
              },
            ],
          },
          h,
        ),
      ],
      tools: [
        h.span([h.Class("meta")], [listing.overview.email]),
        IconButton.view(
          {
            glyph: "log-out",
            label: "Sign out",
            onClick: Message.ClickedSignOut(),
            isDisabled: !Activity.guards.Idle(model.activity),
          },
          h,
        ),
      ],
      toParentMessage: (message) => Message.GotTopBarMessage({ message }),
    },
    h,
  );

const noticesView = (model: Model, h: HtmlBuilder<Message>): ReadonlyArray<Html> => [
  ...(AsyncData.isStale(listingOf(model))
    ? [
        Notice.view(
          {
            title: "Not refreshed",
            body: [NOT_REFRESHED],
            actions: [
              Button.view(
                { label: "retry refresh", isSmall: true, onClick: Message.ClickedRetryListing() },
                h,
              ),
            ],
          },
          h,
        ),
      ]
    : []),
  ...Option.toArray(
    Option.map(refusalAt(model, "Page"), ({ title, reason }) =>
      Notice.view(
        {
          tone: "Error",
          title,
          body: [reason],
          attributes: [h.Id(REFUSAL_ID), h.Tabindex(-1)],
        },
        h,
      ),
    ),
  ),
];

const credentialLabel = (credential: Credential): string =>
  Credential.match(credential, {
    ClientSecret: ({ name }) => `${name} client secret`,
    ApiKey: ({ name }) => `${name} API key`,
  });

const secretOf = (credential: Credential): string =>
  Credential.match(credential, {
    ClientSecret: ({ secret }) => secret,
    ApiKey: ({ key }) => key,
  });

const credentialView = (
  { credential, copy }: PendingCredential,
  h: HtmlBuilder<Message>,
): ReadonlyArray<Html> => {
  const label = credentialLabel(credential);

  const copyButton = h.submodel({
    slotId: CopyButton.id(copy),
    model: copy,
    view: CopyButton.view,
    viewInputs: { text: secretOf(credential), label: `Copy ${label}` },
    toParentMessage: (message) =>
      Message.GotCredentialCopyMessage({ credentialId: credentialId(credential), message }),
  });

  return [
    ...Credential.match(credential, {
      ClientSecret: ({ clientId }) => [
        PropsList.view({ items: [{ label: "client id", value: [clientId], isCode: true }] }, h),
      ],
      ApiKey: () => [],
    }),
    Secret.view({ value: secretOf(credential), label, actions: [copyButton] }, h),
  ];
};

const credentialsView = (model: Model, h: HtmlBuilder<Message>): ReadonlyArray<Html> =>
  Array.match(model.credentials, {
    onEmpty: () => [],
    onNonEmpty: (credentials) => [
      Panel.view(
        {
          id: "credentials",
          title: "New credentials",
          meta: "shown once",
          body: [
            Notice.view(
              {
                glyph: "key",
                title: "Store these now",
                body: [
                  "API keys and client secrets are shown only once. Once dismissed, they cannot be shown again.",
                ],
              },
              h,
            ),
            ...Array.flatMap(credentials, (pending) => credentialView(pending, h)),
            h.div(
              [h.Class("save-row")],
              [
                h.span(
                  [h.Class("push")],
                  [
                    Button.view(
                      {
                        label: "I've stored them",
                        variant: "Primary",
                        onClick: Message.ClickedDismissCredentials(),
                      },
                      h,
                    ),
                  ],
                ),
              ],
            ),
          ],
        },
        h,
      ),
    ],
  });

const issuerView = (model: Model, listing: Listing, h: HtmlBuilder<Message>): Html => {
  const { issuer, email } = listing.overview;

  return Panel.view(
    {
      id: "issuer",
      title: "Issuer",
      meta: "canonical",
      body: [
        PropsList.view(
          {
            items: [
              {
                label: "issuer",
                value: [issuer],
                isCode: true,
                actions: [
                  h.submodel({
                    slotId: CopyButton.id(model.issuerCopy),
                    model: model.issuerCopy,
                    view: CopyButton.view,
                    viewInputs: { text: issuer, label: "Copy issuer" },
                    toParentMessage: (message) => Message.GotIssuerCopyMessage({ message }),
                  }),
                ],
              },
              { label: "signed in as", value: [email] },
            ],
          },
          h,
        ),
      ],
    },
    h,
  );
};

const sectionViews = (
  context: SectionContext,
  section: DashboardRoute,
  h: HtmlBuilder<Message>,
): Readonly<{ head: Html; panels: ReadonlyArray<Html> }> =>
  Match.value(section).pipe(
    Match.tagsExhaustive({
      Clients: () => ({ head: clientsHeadView(context, h), panels: clientsPanels(context, h) }),
      Resources: () => ({
        head: resourcesHeadView(context, h),
        panels: resourcesPanels(context, h),
      }),
      Keys: () => ({ head: keysHeadView(context, h), panels: keysPanels(context, h) }),
    }),
  );

const liveRegionView = (h: HtmlBuilder<Message>) => (): Html => Announcer.view(h);

const editorCardView = (
  model: Model,
  form: Form.Model,
  context: SectionContext,
  render: Dialog.RenderInfo,
  h: HtmlBuilder<Message>,
): Html => {
  const { title, submit } = FormView.labelsOf(form);

  const isFormSaving = isSaving(model);

  return Card.view(
    {
      title,
      titleAttributes: render.title,
      closeAttributes: render.closeButton,
      isCloseHeld: isFormSaving,
      onSubmit: Message.SubmittedForm(),
      actionBarAttributes: render.actionBar,
      actions: [
        Button.view(
          { label: "cancel", isDisabled: isFormSaving, attributes: render.closeButton },
          h,
        ),
        Button.view(
          {
            label: submit,
            type: "submit",
            variant: "Primary",
            isDefault: true,
            isBusy: isFormSaving,
          },
          h,
        ),
      ],
      body: [
        ...Option.toArray(
          Option.map(refusalAt(model, "Editor"), ({ title: refusalTitle, reason }) =>
            Notice.view({ tone: "Error", title: refusalTitle, body: [reason] }, h),
          ),
        ),
        h.submodel({
          slotId: "dashboard-form",
          model: form,
          view: FormView.view,
          viewInputs: {
            resources: Form.Model.guards.Key(form)
              ? grantableResources(context)
              : context.listing.overview.resources,
            isSaving: isFormSaving,
            initialFocus: render.initialFocus,
          },
          toParentMessage: (message) => Message.GotFormMessage({ message }),
        }),
      ],
    },
    h,
  );
};

const editorView = (model: Model, context: SectionContext, h: HtmlBuilder<Message>): Html =>
  h.submodel({
    slotId: Dialog.id(model.editor),
    model: model.editor,
    view: Dialog.view,
    viewInputs: {
      toLiveRegionView:
        Dialog.isOpen(model.editor) && !ConfirmDialog.isOpen(model.confirm)
          ? liveRegionView(h)
          : undefined,
      toView: (render) =>
        Option.match(model.maybeForm, {
          onNone: () => h.empty,
          onSome: (form) => editorCardView(model, form, context, render, h),
        }),
    },
    toParentMessage: (message) => Message.GotEditorMessage({ message }),
  });

const NO_CONFIRMATION = { title: "", question: "", body: "", label: "", isDanger: false };

const confirmView = (model: Model, h: HtmlBuilder<Message>): Html => {
  const isConfirmSaving = isSaving(model);

  const confirmation = Option.getOrElse(pendingConfirmation(model), () => NO_CONFIRMATION);

  return h.submodel({
    slotId: ConfirmDialog.id(model.confirm),
    model: model.confirm,
    view: ConfirmDialog.view,
    viewInputs: {
      title: confirmation.title,
      question: confirmation.question,
      body: [confirmation.body],
      label: confirmation.label,
      isDanger: confirmation.isDanger,
      isBusy: isConfirmSaving,
      isCloseHeld: isConfirmSaving,
      toDetailView: Option.match(refusalAt(model, "Confirm"), {
        onNone: () => undefined,
        onSome:
          ({ title, reason }) =>
          () => [Notice.view({ tone: "Error", title, body: [reason] }, h)],
      }),
      toLiveRegionView: ConfirmDialog.isOpen(model.confirm) ? liveRegionView(h) : undefined,
    },
    toParentMessage: (message) => Message.GotConfirmMessage({ message }),
  });
};

const consoleView = (
  model: Model,
  listing: Listing,
  section: DashboardRoute,
  h: HtmlBuilder<Message>,
): Html => {
  const context: SectionContext = { listing, isHeld: isHeld(model) };

  const { head, panels } = sectionViews(context, section, h);

  return h.div(
    [],
    [
      topBarView(model, listing, section, h),
      Deck.view(
        {
          body: [
            head,
            ...noticesView(model, h),
            ...credentialsView(model, h),
            ...panels,
            issuerView(model, listing, h),
          ],
        },
        h,
      ),
      editorView(model, context, h),
      confirmView(model, h),
    ],
  );
};

export const view = defineView<Model, Message, ViewInputs>((model, { section }, h): Html =>
  AsyncData.match(listingOf(model), {
    onIdle: () => waitingView(h),
    onLoading: () => waitingView(h),
    onFailure: (reason) => unavailableView(reason, h),
    onRefreshing: (listing) => consoleView(model, listing, section, h),
    onStale: ({ data }) => consoleView(model, data, section, h),
    onSuccess: (listing) => consoleView(model, listing, section, h),
  }),
);
