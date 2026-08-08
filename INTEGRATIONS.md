# Connecting Slack & Jira

Both are optional — the app works fine without either. Here's how to turn them on, in plain steps.

## Slack

SentraOps can post straight into a Slack channel — new incident alerts, live investigation progress, and Approve/Reject buttons you can click right from Slack.

**1. Create the Slack app**
- Go to [api.slack.com/apps](https://api.slack.com/apps) → **Create New App** → **From an app manifest**
- Pick the workspace you want to use
- Paste this manifest (swap the URLs if your backend isn't on `localhost:8000`):

```yaml
display_information:
  name: SentraOps
oauth_config:
  redirect_urls:
    - http://localhost:8000/connectors/slack/callback
  scopes:
    bot:
      - chat:write
      - chat:write.public
      - commands
      - channels:read
      - incoming-webhook
features:
  bot_user:
    display_name: SentraOps
  slash_commands:
    - command: /sentraops
      url: http://localhost:8000/slack/commands
      description: Check status, list incidents, or investigate one
settings:
  interactivity:
    is_enabled: true
    request_url: http://localhost:8000/slack/interactions
```
- Click **Create**

**2. Copy your credentials**
- On the app's **Basic Information** page, copy the **Client ID**, **Client Secret**, and **Signing Secret**
- Put them in your `.env` file (`SLACK_CLIENT_ID`, `SLACK_CLIENT_SECRET`, `SLACK_SIGNING_SECRET`), then restart the app

**3. Make Slack able to reach your machine**
Slack's servers need to send slash commands and button clicks to a real, public URL — `localhost` doesn't work for that part. If you're just running this locally, use a free tunnel like [ngrok](https://ngrok.com):
```bash
ngrok http 8000
```
Take the `https://...ngrok-free.app` URL it gives you, and update the **Slash Commands** and **Interactivity** URLs in your Slack app's settings to use it instead of `localhost`. (The OAuth redirect URL can stay as `localhost` — that one only runs in your own browser, not from Slack's side.)

**4. Connect it**
- In SentraOps: **Settings → Integrations**, pick **Slack**, click **Connect to Slack**
- Approve it on Slack's screen and choose a channel — done. Alerts will start appearing there.

## Jira

SentraOps can open a real Jira ticket automatically whenever a proposed response action gets approved.

**1. Get a free Jira account** (skip if you already have one)
- Sign up at [atlassian.com/software/jira/free](https://www.atlassian.com/software/jira/free) — no credit card needed
- Create a project (Kanban template is easiest) and note its **project key** — shown near the project name, e.g. `SCRUM`

**2. Create an API token**
- Go to [id.atlassian.com/manage-profile/security/api-tokens](https://id.atlassian.com/manage-profile/security/api-tokens) → **Create API token** → copy it (it's only shown once)

**3. Add it in SentraOps**
- **Settings → Integrations → Response Action Integrations**, pick **Jira**, fill in:

| Field | What to put |
|---|---|
| `base_url` | Your Jira site, e.g. `https://yourname.atlassian.net` |
| `email` | The email you signed up with |
| `api_token` | From step 2 |
| `project_key` | From step 1 |

- Click **Add Integration** — no restart needed, this one's entirely set up through the UI.

Approve any proposed action afterward and a real ticket shows up in your Jira project.

**4. (Optional) Sync ticket resolution back to SentraOps**

By default this integration is one-way: SentraOps → Jira. Resolving the Jira ticket does nothing to the incident on its own. To make completing the ticket automatically close the SentraOps incident it was created for:

- In SentraOps: `GET /connectors/jira/webhook-url` (owner/admin only — call it with your bearer token, e.g. from the browser dev console or `curl`) returns a one-time-generated URL like `https://your-backend.onrender.com/webhooks/jira/{your-org-slug}/{secret}`
- In Jira: **Project settings → Automation → Create rule**
  - Trigger: **Issue transitioned** → select your "Done"/resolved status
  - New action: **Send web request** → paste the URL from above, method `POST`, body `{{issue}}` (Jira's automation web request already sends the issue JSON when left as the default webhook body)
  - Save and enable the rule

The secret is embedded in the URL path itself (same pattern as a Slack/Discord incoming webhook) since Jira Automation's web request action can't send a custom Authorization header on the free/standard plan. Only paste this URL into Jira's own automation config — anyone with it can close incidents in your org. SentraOps matches the incoming Jira issue key against the ticket it created for each approved action, so this only ever closes the incident that ticket was opened for.
