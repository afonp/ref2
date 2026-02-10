/// Graphviz DOT serialiser.

use std::io::{self, Write};
use crate::grammar::Fsm;

pub fn emit<W: Write>(out: &mut W, fsm: &Fsm) -> io::Result<()> {
    writeln!(out, "digraph protocol {{")?;
    writeln!(out, "    rankdir=LR;")?;
    writeln!(out, "    node [shape=circle fontname=\"Helvetica\"];")?;
    writeln!(out, "    edge [fontname=\"Helvetica\" fontsize=10];")?;
    writeln!(out)?;

    for s in &fsm.states {
        let shape = if s.is_accepting { "doublecircle" } else { "circle" };
        let extra = if s.is_initial { " style=filled fillcolor=lightblue" } else { "" };
        writeln!(out, "    S{id} [shape={shape} label=\"{label}\"{extra}];",
                 id    = s.id,
                 shape = shape,
                 label = s.label,
                 extra = extra)?;
    }

    writeln!(out)?;

    for t in &fsm.transitions {
        let pct = (t.frequency * 100.0).round() as u32;
        writeln!(
            out,
            "    S{from} -> S{to} [label=\"{schema}\\n({pct}%)\"];",
            from   = t.from,
            to     = t.to,
            schema = t.schema_ref,
            pct    = pct,
        )?;
    }

    writeln!(out, "}}")
}
