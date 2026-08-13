#!/usr/bin/env python3
"""Build the Elemta dashboard in Kibana, and export it as a file.

Kibana dashboards are saved objects, and hand-writing their JSON is how you get
a dashboard that imports cleanly and renders nothing. This creates the panels
through the API against a live Kibana — so a panel that Kibana will not accept
fails here rather than in front of somebody — and then exports the result to
deployments/elk/elemta-dashboard.ndjson so it can be re-imported anywhere.

  python3 scripts/dev/build_elk_dashboard.py            # build and export
  python3 scripts/dev/build_elk_dashboard.py --export-only
"""

import argparse
import json
import os
import sys
import urllib.error
import urllib.request

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
EXPORT_PATH = os.path.join(REPO, "deployments", "elk", "elemta-dashboard.ndjson")
DASHBOARD_ID = "elemta-overview"


def kibana(method, path, body=None, base="http://localhost:5601", raw=False):
    data = None
    if body is not None:
        data = body.encode() if isinstance(body, str) else json.dumps(body).encode()
    request = urllib.request.Request(base + path, data=data, method=method)
    request.add_header("kbn-xsrf", "true")
    if body is not None:
        # raw controls how the response is read, not how the request is sent.
        # Omitting this header made Kibana treat the export body as an opaque
        # string and report the whole thing as a missing key.
        request.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            payload = response.read()
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode(errors="replace")[:400]
        raise SystemExit(f"Kibana {method} {path} failed: {exc.code}\n{detail}")
    except urllib.error.URLError as exc:
        raise SystemExit(f"Kibana is not reachable at {base}: {exc.reason}\n"
                         f"Start it with 'make elk-up'.")
    if raw:
        return payload.decode()
    return json.loads(payload) if payload else {}


def data_view_id():
    """Find the elemta-* data view, which every panel references."""
    for view in kibana("GET", "/api/data_views").get("data_view", []):
        if view.get("title") == "elemta-*":
            return view["id"]
    raise SystemExit("No elemta-* data view. Run 'make elk-data-view' first.")


def count_column(label, query=None):
    return {"label": label, "dataType": "number", "operationType": "count",
            "isBucketed": False, "sourceField": "___records___",
            **({"filter": {"language": "kuery", "query": query}} if query else {})}


def lens(title, visualization_type, layer, visualization, query=""):
    """One Lens panel. Layers and references are wired up the same way each
    time, because a mismatched layer id is the failure that produces an empty
    panel rather than an error."""
    return {
        "title": title,
        "visualizationType": visualization_type,
        "state": {
            "datasourceStates": {"formBased": {"layers": {"L1": layer}}},
            "filters": [],
            "query": {"language": "kuery", "query": query},
            "visualization": visualization,
        },
    }


def panels(dv):
    """The dashboard, as a list of (id, lens attributes).

    Chosen for the questions an operator actually asks during a load test:
    is mail flowing, is it being accepted, what are the scanners finding, how
    long is it taking, and is anything going wrong.
    """
    out = []

    # Throughput over time. The first question is always "is it moving".
    out.append(("elemta-throughput", lens(
        "Messages accepted over time", "lnsXY",
        {"columns": {
            "time": {"label": "@timestamp", "dataType": "date", "operationType": "date_histogram",
                     "sourceField": "@timestamp", "isBucketed": True,
                     "params": {"interval": "auto"}},
            "count": count_column("Accepted")},
         "columnOrder": ["time", "count"], "incompleteColumns": {}},
        {"legend": {"isVisible": True, "position": "right"}, "preferredSeriesType": "bar_stacked",
         "layers": [{"layerId": "L1", "layerType": "data", "seriesType": "bar_stacked",
                     "xAccessor": "time", "accessors": ["count"]}]},
        query='event_type: "message_accepted"')))

    # Accepted against rejected. A throughput chart alone cannot tell the
    # difference between healthy traffic and a server refusing all of it.
    out.append(("elemta-outcomes", lens(
        "Accepted vs rejected", "lnsXY",
        {"columns": {
            "time": {"label": "@timestamp", "dataType": "date", "operationType": "date_histogram",
                     "sourceField": "@timestamp", "isBucketed": True,
                     "params": {"interval": "auto"}},
            "ok": count_column("Accepted", 'event_type: "message_accepted"'),
            "bad": count_column("Rejected", 'msg: "message_scanned" and passed: false')},
         "columnOrder": ["time", "ok", "bad"], "incompleteColumns": {}},
        {"legend": {"isVisible": True, "position": "right"}, "preferredSeriesType": "bar",
         "layers": [{"layerId": "L1", "layerType": "data", "seriesType": "bar",
                     "xAccessor": "time", "accessors": ["ok", "bad"],
                     # Rejections on their own axis, because they are rare by
                     # design and a shared axis hides them. Measured on a real
                     # run: 35,000 accepted against 180 rejected puts the
                     # rejected bar below one pixel, so a server refusing
                     # everything it should and a server refusing nothing look
                     # identical — which is the one distinction this panel
                     # exists to draw.
                     "yConfig": [{"forAccessor": "bad", "axisMode": "right"}]}]})))

    # Why the delay climbs.
    #
    # The latency panel shows reception-to-delivery, which under load is mostly
    # queue wait, and a rising line there says nothing about the cause. This
    # says it directly: mail entering the queue against mail leaving it. On a
    # stress run Elemta accepted ~6,600 a minute and delivered ~1,000, so the
    # gap accumulated and the delay grew linearly until the run stopped and the
    # queue drained. Two lines that separate are a server falling behind.
    out.append(("elemta-backlog", lens(
        "Into the queue vs out of it", "lnsXY",
        {"columns": {
            "time": {"label": "@timestamp", "dataType": "date", "operationType": "date_histogram",
                     "sourceField": "@timestamp", "isBucketed": True,
                     "params": {"interval": "auto"}},
            "in": count_column("Accepted into the queue", 'event_type: "message_accepted"'),
            "out": count_column("Delivered out of it", 'event_type: "delivery"')},
         "columnOrder": ["time", "in", "out"], "incompleteColumns": {}},
        {"legend": {"isVisible": True, "position": "right"}, "preferredSeriesType": "line",
         "layers": [{"layerId": "L1", "layerType": "data", "seriesType": "line",
                     "xAccessor": "time", "accessors": ["in", "out"]}]})))

    # What the scanners found. This is the panel the scan-verdict logging was
    # added for: the verdict used to be a Debug line and reached nothing.
    out.append(("elemta-scan-verdicts", lens(
        "Scanner verdicts", "lnsPie",
        {"columns": {
            "verdict": {"label": "Verdict", "dataType": "string", "operationType": "filters",
                        "isBucketed": True,
                        "params": {"filters": [
                            {"input": {"language": "kuery", "query": "virus_found: true"}, "label": "Virus"},
                            {"input": {"language": "kuery", "query": "spam_detected: true and virus_found: false"}, "label": "Spam"},
                            {"input": {"language": "kuery", "query": "virus_found: false and spam_detected: false"}, "label": "Clean"}]}},
            "count": count_column("Messages")},
         "columnOrder": ["verdict", "count"], "incompleteColumns": {}},
        {"shape": "donut", "layers": [{"layerId": "L1", "layerType": "data",
                                       "primaryGroups": ["verdict"], "metrics": ["count"],
                                       "numberDisplay": "value", "categoryDisplay": "default",
                                       "legendDisplay": "default"}]},
        query='msg: "message_scanned"')))

    # Where messages land relative to the spam threshold.
    #
    # The verdict donut above answers "how much was flagged" and, on this dev
    # stack, answers it with "almost all of it" — which looks like a broken
    # scanner until you see the scores. Clean corpus mail scores around 9.4
    # (no SPF, no DKIM, no rDNS for the sending domain) and GTUBE scores 15-17,
    # against a threshold of 6.0. Two clear clusters, both above the line.
    # A binary panel cannot show that; these bands can, which is what makes the
    # difference between a dashboard that alarms and one that explains.
    out.append(("elemta-spam-scores", lens(
        "Spam scores against the threshold", "lnsXY",
        {"columns": {
            "band": {"label": "Score", "dataType": "string", "operationType": "filters",
                     "isBucketed": True,
                     "params": {"filters": [
                         {"input": {"language": "kuery", "query": "spam_score < 6"}, "label": "under 6 (below threshold)"},
                         {"input": {"language": "kuery", "query": "spam_score >= 6 and spam_score < 10"}, "label": "6 to 10"},
                         {"input": {"language": "kuery", "query": "spam_score >= 10 and spam_score < 15"}, "label": "10 to 15"},
                         {"input": {"language": "kuery", "query": "spam_score >= 15"}, "label": "15 and over"}]}},
            "count": count_column("Messages")},
         "columnOrder": ["band", "count"], "incompleteColumns": {}},
        {"legend": {"isVisible": False, "position": "right"}, "preferredSeriesType": "bar",
         "layers": [{"layerId": "L1", "layerType": "data", "seriesType": "bar",
                     "xAccessor": "band", "accessors": ["count"]}]},
        query='msg: "message_scanned"')))

    # Delivery latency. An average hides the tail, and the tail is what an
    # operator notices, so the percentiles are shown rather than the mean.
    out.append(("elemta-latency", lens(
        "Delivery delay (median and 95th percentile)", "lnsXY",
        {"columns": {
            "time": {"label": "@timestamp", "dataType": "date", "operationType": "date_histogram",
                     "sourceField": "@timestamp", "isBucketed": True,
                     "params": {"interval": "auto"}},
            "p50": {"label": "median ms", "dataType": "number", "operationType": "percentile",
                    "sourceField": "total_delay_ms", "isBucketed": False, "params": {"percentile": 50}},
            "p95": {"label": "95th percentile ms", "dataType": "number", "operationType": "percentile",
                    "sourceField": "total_delay_ms", "isBucketed": False, "params": {"percentile": 95}}},
         "columnOrder": ["time", "p50", "p95"], "incompleteColumns": {}},
        {"legend": {"isVisible": True, "position": "right"}, "preferredSeriesType": "line",
         "layers": [{"layerId": "L1", "layerType": "data", "seriesType": "line",
                     "xAccessor": "time", "accessors": ["p50", "p95"]}]},
        query='event_type: "delivery"')))

    # Warnings and errors over time, which is where an incident first shows.
    out.append(("elemta-problems", lens(
        "Warnings and errors", "lnsXY",
        {"columns": {
            "time": {"label": "@timestamp", "dataType": "date", "operationType": "date_histogram",
                     "sourceField": "@timestamp", "isBucketed": True,
                     "params": {"interval": "auto"}},
            "level": {"label": "Level", "dataType": "string", "operationType": "terms",
                      "sourceField": "log.level", "isBucketed": True,
                      "params": {"size": 3, "orderBy": {"type": "column", "columnId": "count"},
                                 "orderDirection": "desc"}},
            "count": count_column("Events")},
         "columnOrder": ["time", "level", "count"], "incompleteColumns": {}},
        {"legend": {"isVisible": True, "position": "right"}, "preferredSeriesType": "bar_stacked",
         "layers": [{"layerId": "L1", "layerType": "data", "seriesType": "bar_stacked",
                     "xAccessor": "time", "splitAccessor": "level", "accessors": ["count"]}]},
        query='log.level: ("WARN" or "ERROR")')))

    # Which part of the server is talking. Useful for finding the component
    # responsible when something starts shouting.
    out.append(("elemta-components", lens(
        "Events by component", "lnsDatatable",
        {"columns": {
            "component": {"label": "Component", "dataType": "string", "operationType": "terms",
                          "sourceField": "component", "isBucketed": True,
                          "params": {"size": 15, "orderBy": {"type": "column", "columnId": "count"},
                                     "orderDirection": "desc"}},
            "count": count_column("Events")},
         "columnOrder": ["component", "count"], "incompleteColumns": {}},
        {"layerId": "L1", "layerType": "data",
         "columns": [{"columnId": "component"}, {"columnId": "count"}]})))

    return [(pid, attrs, dv) for pid, attrs in out]


def build():
    dv = data_view_id()
    created = []
    for panel_id, attrs, view in panels(dv):
        # Overwrite so the script is safe to re-run after editing a panel.
        kibana("POST", f"/api/saved_objects/lens/{panel_id}?overwrite=true", {
            "attributes": attrs,
            "references": [{"type": "index-pattern", "id": view,
                            "name": "indexpattern-datasource-layer-L1"}],
        })
        created.append(panel_id)
        print(f"  panel  {panel_id}")

    # Two panels per row, in the order an investigation tends to go.
    references, panels_json = [], []
    for index, panel_id in enumerate(created):
        name = f"panel_{index}"
        references.append({"type": "lens", "id": panel_id, "name": f"{name}:panel_{name}"})
        panels_json.append({
            "version": "8.15.3", "type": "lens", "gridData": {
                "x": 0 if index % 2 == 0 else 24, "y": (index // 2) * 15,
                "w": 24, "h": 15, "i": name},
            "panelIndex": name, "embeddableConfig": {"enhancements": {}}, "panelRefName": f"panel_{name}"})

    kibana("POST", f"/api/saved_objects/dashboard/{DASHBOARD_ID}?overwrite=true", {
        "attributes": {
            "title": "Elemta overview",
            "description": "Throughput, acceptance, scanner verdicts, delay and problems.",
            "panelsJSON": json.dumps(panels_json),
            "optionsJSON": json.dumps({"hidePanelTitles": False, "useMargins": True}),
            "timeRestore": True,
            "timeFrom": "now-1h", "timeTo": "now",
            "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps({"query": {"language": "kuery", "query": ""}, "filter": []})},
        },
        "references": references,
    })
    print(f"  dashboard {DASHBOARD_ID}")


def export():
    body = {"objects": [{"type": "dashboard", "id": DASHBOARD_ID}], "includeReferencesDeep": True}
    ndjson = kibana("POST", "/api/saved_objects/_export", body, raw=True)
    os.makedirs(os.path.dirname(EXPORT_PATH), exist_ok=True)
    with open(EXPORT_PATH, "w", encoding="utf-8") as handle:
        handle.write(ndjson)
    objects = [line for line in ndjson.splitlines() if line.strip()]
    print(f"  exported {len(objects)} saved objects to "
          f"{os.path.relpath(EXPORT_PATH, REPO)}")


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--export-only", action="store_true",
                        help="Export the dashboard already in Kibana without rebuilding it")
    args = parser.parse_args()

    if not args.export_only:
        build()
    export()
    print("\nOpen it at http://localhost:5601/app/dashboards")
    return 0


if __name__ == "__main__":
    sys.exit(main())
