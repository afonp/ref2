---
sidebar_position: 3
---

# ref2 view

render a graphviz dot file and open it in a viewer.

## synopsis

```
ref2 view <dot_file>
```

## description

attempts to render the dot file to svg using `dot(1)`, then opens the svg in the default application (`open` on macos, `xdg-open` on linux).

if `dot` is not installed, it prints the path to the dot file and exits cleanly.

## installing graphviz

```bash
brew install graphviz       # macos
sudo apt install graphviz   # debian / ubuntu
sudo dnf install graphviz   # fedora
```

## manual rendering

```bash
# svg
dot -Tsvg ref2_output/fsm.dot -o ref2_output/fsm.svg

# png
dot -Tpng ref2_output/fsm.dot -o ref2_output/fsm.png

# pdf
dot -Tpdf ref2_output/fsm.dot -o ref2_output/fsm.pdf
```

## example dot output

a typical fsm for a simple request-response protocol:

```dot
digraph protocol {
    rankdir=LR;
    node [shape=circle fontname="Helvetica"];
    edge [fontname="Helvetica" fontsize=10];

    S0 [shape=doublecircle label="INIT" style=filled fillcolor=lightblue];
    S1 [shape=circle label="S1"];
    S2 [shape=doublecircle label="S2"];

    S0 -> S1 [label="msg_type_00\n(100%)"];
    S1 -> S2 [label="msg_type_01\n(94%)"];
    S2 -> S2 [label="msg_type_02\n(87%)"];
    S2 -> S0 [label="msg_type_03\n(61%)"];
}
```
