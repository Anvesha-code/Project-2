import matplotlib.pyplot as plt
import networkx as nx
from pptx import Presentation
from pptx.util import Inches, Pt

# ---------------------------------------------------------------
# BUILD EDGES WITH LABELS
# ---------------------------------------------------------------
def build_edges_with_labels(api_response):
    pages = api_response.get("pages", [])
    edges = api_response.get("edges", [])

    # Map page ID -> page label
    id_to_label = {page["id"]: page["label"] for page in pages}

    # Build edges as tuples: (source_label, target_label, edge_label)
    enriched_edges = [
        (
            id_to_label.get(edge["source"], edge["source"]),
            id_to_label.get(edge["target"], edge["target"]),
            edge.get("label", "")
        )
        for edge in edges
    ]
    return enriched_edges

# ---------------------------------------------------------------
# LAYOUT WITHOUT GRAPHVIZ
# ---------------------------------------------------------------
def get_layout(G, layout_type):
    if layout_type in ["flowchart", "tree", "mindmap"]:
        pos = nx.spring_layout(G, k=2, iterations=50)
        return pos
    if layout_type == "circular":
        return nx.circular_layout(G)
    raise ValueError(f"Unknown layout: {layout_type}")

# ---------------------------------------------------------------
# DRAW GRAPH
# ---------------------------------------------------------------
def save_matplotlib(G, pos, file_prefix):
    plt.figure(figsize=(12, 8))
    edge_labels = nx.get_edge_attributes(G, "label")
    nx.draw(
        G, pos,
        with_labels=True,
        arrows=True,
        node_size=3000,
        node_color="lightblue",
        edge_color="black",
        linewidths=1.5,
        font_size=9
    )
    nx.draw_networkx_edge_labels(G, pos, edge_labels=edge_labels, font_color="red", font_size=8)
    plt.tight_layout()
    plt.savefig(f"{file_prefix}.png", dpi=300)
    plt.savefig(f"{file_prefix}.svg")
    plt.savefig(f"{file_prefix}.pdf")
    plt.close()

# ---------------------------------------------------------------
# OPTIONAL PPTX
# ---------------------------------------------------------------
def save_pptx(G, pos, file_prefix):
    prs = Presentation()
    slide = prs.slides.add_slide(prs.slide_layouts[6])

    min_x = min(p[0] for p in pos.values())
    max_x = max(p[0] for p in pos.values())
    min_y = min(p[1] for p in pos.values())
    max_y = max(p[1] for p in pos.values())

    def norm(v, vmin, vmax):
        return (v - vmin) / (vmax - vmin + 1e-6)

    node_positions = {}

    # Add nodes
    for node, (x, y) in pos.items():
        left = Inches(norm(x, min_x, max_x) * 9)
        top = Inches(norm(-y, min_y, max_y) * 5)
        shape = slide.shapes.add_shape(1, left, top, Inches(1.5), Inches(0.6))
        shape.text = node
        node_positions[node] = (left, top)

    # Add connectors
    for (u, v, d) in G.edges(data=True):
        start_x, start_y = node_positions[u]
        end_x, end_y = node_positions[v]
        line = slide.shapes.add_connector(1, start_x, start_y, end_x, end_y)
        line.line.width = Pt(1.2)

    prs.save(f"{file_prefix}.pptx")

# ---------------------------------------------------------------
# MAIN FUNCTION
# ---------------------------------------------------------------
def generate_diagram(api_response, layout_type="flowchart", generate_pptx=False):
    edges = build_edges_with_labels(api_response)
    G = nx.DiGraph()
    for src, tgt, lbl in edges:
        G.add_edge(src, tgt, label=lbl)

    pos = get_layout(G, layout_type)
    file_prefix = f"diagram_{layout_type}"

    save_matplotlib(G, pos, file_prefix)
    if generate_pptx:
        save_pptx(G, pos, file_prefix)

    print(f"Generated {file_prefix}.*")

# ---------------------------------------------------------------
# EXAMPLE MULTI-PAGE & MULTI-EDGE API RESPONSE
# ---------------------------------------------------------------
if _name_ == "_main_":
    api_response = {
        "pages": [
            {
                "id": "page1",
                "label": "Home Page",
                "metadata": {
                    "url": "/home",
                    "elements": [
                        {"id": "1", "text": "Login", "type": "button"},
                        {"id": "2", "text": "Support", "type": "link"}
                    ]
                }
            },
            {
                "id": "page2",
                "label": "Login Page",
                "metadata": {
                    "url": "/login",
                    "elements": [
                        {"id": "3", "text": "Email", "type": "input"},
                        {"id": "4", "text": "Password", "type": "input"}
                    ]
                }
            },
            {
                "id": "page3",
                "label": "Dashboard Page",
                "metadata": {
                    "url": "/dashboard",
                    "elements": [
                        {"id": "5", "text": "Welcome", "type": "text"}
                    ]
                }
            },
            {
                "id": "page4",
                "label": "Settings Page",
                "metadata": {
                    "url": "/settings",
                    "elements": [
                        {"id": "6", "text": "Preferences", "type": "form"}
                    ]
                }
            },
            {
                "id": "page5",
                "label": "Profile Page",
                "metadata": {
                    "url": "/profile",
                    "elements": [
                        {"id": "7", "text": "Edit Profile", "type": "button"}
                    ]
                }
            }
        ],
        "edges": [
            {"id": "edge1", "source": "page1", "target": "page2", "label": "Click Login"},
            {"id": "edge2", "source": "page2", "target": "page3", "label": "Submit Form"},
            {"id": "edge3", "source": "page3", "target": "page4", "label": "Go to Settings"},
            {"id": "edge4", "source": "page4", "target": "page5", "label": "Update Profile"},
            {"id": "edge5", "source": "page1", "target": "page3", "label": "Quick Access Dashboard"}
        ]
    }

    generate_diagram(api_response, layout_type="flowchart", generate_pptx=False)
