from langgraph.graph import END, StateGraph

from app.agents import detection, investigation, report, response, risk, threat_intel
from app.agents.state import AgentState, build_initial_state


def _build_graph():
    graph = StateGraph(AgentState)
    graph.add_node("detection", detection.run)
    graph.add_node("investigation", investigation.run)
    graph.add_node("threat_intel", threat_intel.run)
    graph.add_node("risk", risk.run)
    graph.add_node("response", response.run)
    graph.add_node("report", report.run)

    # Linear hand-off for now, exactly like a human SOC manager routing one
    # incident through the team in a fixed order - the Coordinator doesn't
    # reason itself, it owns the sequence and lets each specialist read
    # everything the ones before it found via the shared AgentState.
    graph.set_entry_point("detection")
    graph.add_edge("detection", "investigation")
    graph.add_edge("investigation", "threat_intel")
    graph.add_edge("threat_intel", "risk")
    graph.add_edge("risk", "response")
    graph.add_edge("response", "report")
    graph.add_edge("report", END)

    return graph.compile()


_GRAPH = _build_graph()


def run_investigation(
    incident,
    timeline: list[dict],
    assets: list[dict] | None = None,
    memory: dict | None = None,
    graph_context: dict | None = None,
) -> AgentState:
    """Runs the full Detection -> Investigation -> Threat Intel -> Risk ->
    Response -> Report chain for one incident and returns the final shared
    state, including the accumulated inter-agent message log. `memory` is
    the cross-incident institutional history from agents/memory.py -
    similar past incidents and repeat-offender hosts/users. `graph_context`
    is the real Neo4j blast-radius traversal from agents/graph_context.py -
    so the team doesn't investigate every incident from a blank slate."""
    initial_state = build_initial_state(incident, timeline, assets, memory, graph_context)
    return _GRAPH.invoke(initial_state)


def stream_investigation(
    incident,
    timeline: list[dict],
    assets: list[dict] | None = None,
    memory: dict | None = None,
    graph_context: dict | None = None,
):
    """Same chain as run_investigation, but yields (agent_name, state)
    after each agent completes instead of blocking until the whole chain
    finishes - the hook the async task/WebSocket path streams live
    progress from. The state yielded after the last agent is exactly what
    run_investigation() would have returned, since no node here declares a
    custom reducer (each node's return dict is just merged into the
    accumulated state, the same as LangGraph's default `invoke` behavior)."""
    state = dict(build_initial_state(incident, timeline, assets, memory, graph_context))
    for update in _GRAPH.stream(state, stream_mode="updates"):
        for node_name, partial in update.items():
            state.update(partial)
            yield node_name, state
