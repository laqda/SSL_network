use std::sync::Arc;
use petgraph::{Graph, Directed};
use std::collections::HashMap;
use petgraph::graph::NodeIndex;

type NetEdge = Vec<u8>;
type NetGraph = Graph<Equipment, NetEdge, Directed, u32>;

pub struct Network {
    graph: NetGraph,
    nodes: HashMap<Vec<u8>, usize>,
}

impl Network {
    pub fn new(root_eq: Equipment) -> Network {
        let mut n = Network {
            graph: Graph::new(),
            nodes: HashMap::new(),
        };
        n.add_equipment(root_eq);
        n
    }
    pub fn add_equipment(&mut self, eq : Equipment) {
        let pub_key = eq.pub_key.clone();
        let i = self.graph.add_node(eq).index();
        self.nodes.insert(pub_key, i);
    }
    pub fn add_certification(&mut self, subject_pub_key: Vec<u8>, issuer_pub_key: Vec<u8>, cert: Vec<u8>) {
        let subject = self.nodes.get(&subject_pub_key).unwrap();
        let issuer = self.nodes.get(&issuer_pub_key).unwrap();
        self.graph.add_edge(NodeIndex::new(issuer.clone()), NodeIndex::new(subject.clone()), cert);
    }
    pub fn contains(&self, pub_key: &Vec<u8>) -> bool {
        self.nodes.contains_key(pub_key)
    }
}


pub struct Equipment {
    name: String,
    pub_key: Vec<u8>,
}

impl Equipment {
    pub fn new(name: String, pub_key: Vec<u8>) -> Equipment {
        Equipment {
            name,
            pub_key,
        }
    }
}
