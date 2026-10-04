# Stop the Claude subscription-credential server

Accepted on 2026-10-04. HQ applied the rule 33 default after the 30-minute decision window elapsed without Amir's response and reported the decision in `goal.md`: stop the Claude subscription-credential server work. The C1 terms assessment concluded **not allowed** for a custom server that stores subscription refresh credentials, refreshes them, and distributes access tokens, including when all clients belong to one person.

The supporting research is `/home/amir/b21/claudectl-terms.md` (2026-10-04, local HQ artifact). The relevant quotations and public primary sources are reproduced here so this decision can be reviewed without access to that file.

[Anthropic's Claude Code credential policy](https://code.claude.com/docs/en/legal-and-compliance#authentication-and-credential-use) states:

> Moreover, developers may not collect, store, or intermediate Claude.ai credentials or session tokens — sign-in to a Claude account must complete through Anthropic's own flow.

Company SSO, exclusive refresh ownership, and delivery only to unmodified Claude Code do not remove the proposed server's credential custody. Successful technical experiments do not establish permission. This decision supersedes the earlier acceptance of provider risk in [claudectl#14](https://github.com/Sawmills/claudectl/pull/14).

The [Consumer Terms, §2](https://www.anthropic.com/legal/consumer-terms) also prohibit sharing an individual subscription account:

> You may not share your Account login information, Anthropic API key, or Account credentials with anyone else. You also may not make your Account available to anyone else.

## Allowed alternatives

- **Company API keys in a secrets manager**, for the company's own authorized users, with usage billed to the key owner under the applicable commercial agreement. The consumer account restriction above does not negate the explicit commercial API-key allowance below.
- **Assigned Team/Enterprise seats with native login** through Anthropic's flow. Each user signs into their invited account; seats do not create an exception permitting a custom subscription credential broker.

The [credential policy](https://code.claude.com/docs/en/legal-and-compliance#authentication-and-credential-use) expressly preserves company API-key management:

> This does not restrict how customers provision and manage their own API keys or third-party inference provider credentials — for example, configuring an API key in a development environment, secrets manager, or machine image for use by the customer's own authorized users — provided the resulting usage is billed to the key owner under their agreement with Anthropic (or the applicable provider) and is not resold or intermediated as described above.

The [Team/Enterprise authentication documentation](https://code.claude.com/docs/en/authentication#claude-for-teams-or-enterprise) states:

> Team members install Claude Code and log in with their claude.ai accounts.

Anthropic also documents native hosted sign-in and [`claude setup-token` for CI](https://code.claude.com/docs/en/authentication#generate-a-long-lived-token). This decision concerns the proposed credential broker; those supported workflows do not authorize an independent subscription refresh service.

## Consequences

Mark the server parts of [claudectl#15](https://github.com/Sawmills/claudectl/pull/15) and [codexctl#74](https://github.com/Sawmills/codexctl/pull/74) **not pursued**, keep both PRs as drafts, and retain their branches as historical work. Their earlier deployment and migration next steps are superseded: do not continue implementation, migrate credentials, deploy, or merge the subscription broker.

The alternatives above are available directions, not authorization to implement a replacement in this closeout. Reopening the broker would require an express Anthropic authorization for this arrangement or a documented policy change, followed by a new project decision.
