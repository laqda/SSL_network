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
    pub fn add_equipment(&mut self, eq: Equipment) {
        let pub_key = eq.pub_key.clone();
        let i = self.graph.add_node(eq).index();
        self.nodes.insert(pub_key, i);
    }
    pub fn add_certification(&mut self, subject_name: String, subject_pub_key: Vec<u8>, issuer_name: String, issuer_pub_key: Vec<u8>, cert: Vec<u8>) {
        if !self.nodes.contains_key(&subject_pub_key) {
            self.add_equipment(Equipment::new(subject_name.clone(), subject_pub_key.clone()));
        }
        if !self.nodes.contains_key(&issuer_pub_key) {
            self.add_equipment(Equipment::new(issuer_name.clone(), issuer_pub_key.clone()));
        }
        let subject = self.nodes.get(&subject_pub_key).unwrap();
        let issuer = self.nodes.get(&issuer_pub_key).unwrap();
        self.graph.add_edge(NodeIndex::new(issuer.clone()), NodeIndex::new(subject.clone()), cert);
        if self.graph.node_weight(NodeIndex::new(issuer.clone())).unwrap().verified {
            let subject = self.graph.node_weight_mut(NodeIndex::new(subject.clone())).unwrap();
            subject.verified = true;
            // TODO verify if subject becoming verified implies others to become verified
        }
    }
    pub fn is_verified(&self, pub_key: &Vec<u8>) -> bool {
        if self.nodes.contains_key(pub_key) {
            let node = self.nodes.get(pub_key).unwrap();
            let node = self.graph.node_weight(NodeIndex::new(node.clone())).unwrap();
            return node.verified;
        }
        false
    }
}

#[allow(dead_code)]
pub struct Equipment {
    name: String,
    pub_key: Vec<u8>,
    pub verified: bool,
}

impl Equipment {
    pub fn new(name: String, pub_key: Vec<u8>) -> Equipment {
        Equipment {
            name,
            pub_key,
            verified: false,
        }
    }
    pub fn root(name: String, pub_key: Vec<u8>) -> Equipment {
        Equipment {
            name,
            pub_key,
            verified: true,
        }
    }
}
