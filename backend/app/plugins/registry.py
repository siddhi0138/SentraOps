from app.plugins.base import ConnectorPlugin, ResponseActionPlugin

_CONNECTORS: dict[str, ConnectorPlugin] = {}
_ACTIONS: dict[str, ResponseActionPlugin] = {}


def register_connector(plugin: ConnectorPlugin) -> None:
    _CONNECTORS[plugin.key] = plugin


def register_action(plugin: ResponseActionPlugin) -> None:
    _ACTIONS[plugin.key] = plugin


def get_connector(key: str) -> ConnectorPlugin:
    try:
        return _CONNECTORS[key]
    except KeyError:
        raise ValueError(f"Unknown connector plugin '{key}'. Available: {sorted(_CONNECTORS)}")


def get_action(key: str) -> ResponseActionPlugin:
    try:
        return _ACTIONS[key]
    except KeyError:
        raise ValueError(f"Unknown response-action plugin '{key}'. Available: {sorted(_ACTIONS)}")


def list_connectors() -> list[dict]:
    return [
        {
            "key": p.key,
            "display_name": p.display_name,
            "category": p.category,
            "config_fields": p.config_fields,
            "auth_type": p.auth_type,
        }
        for p in _CONNECTORS.values()
    ]


def list_actions() -> list[dict]:
    return [
        {"key": p.key, "display_name": p.display_name, "categories": p.categories, "config_fields": p.config_fields}
        for p in _ACTIONS.values()
    ]


def _load_builtin_plugins() -> None:
    from app.plugins.connectors import generic_rest, github_events, slack, urlhaus
    from app.plugins.actions import jira, servicenow, webhook

    register_connector(urlhaus.UrlhausConnector())
    register_connector(github_events.GitHubEventsConnector())
    register_connector(generic_rest.GenericRestConnector())
    register_connector(slack.SlackConnector())
    register_action(webhook.WebhookAction())
    register_action(jira.JiraAction())
    register_action(servicenow.ServiceNowAction())


_load_builtin_plugins()
