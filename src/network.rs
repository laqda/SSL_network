use serde::{Serialize, Deserialize};
use petgraph::{Graph, Directed};
use std::collections::HashMap;
use petgraph::graph::{NodeIndex, node_index};
use petgraph::visit::{depth_first_search, DfsEvent, Control};
use crate::shared_types::{PublicKey, Certificate};
use openssl::x509::X509;

type NetEdge = Certificate;
type NetGraph = Graph<Equipment, NetEdge, Directed, u32>;

#[derive(Clone)]
pub struct Network {
    root_node: usize,
    root_node_pub_key: PublicKey,
    graph: NetGraph,
    nodes: HashMap<NetEdge, usize>,
}

impl Network {
    pub fn new(root_eq: Equipment) -> Network {
        let mut n = Network {
            graph: Graph::new(),
            nodes: HashMap::new(),
            root_node: 0,
            root_node_pub_key: root_eq.pub_key.clone(),
        };
        let i = n.add_equipment(root_eq);
        n.root_node = i;
        n
    }
    pub fn add_equipment(&mut self, eq: Equipment) -> usize {
        let pub_key = eq.pub_key.clone();
        let i = self.graph.add_node(eq).index();
        self.nodes.insert(pub_key, i);
        i
    }
    pub fn add_certification(&mut self, subject_name: String, subject_pub_key: PublicKey, issuer_name: String, issuer_pub_key: PublicKey, cert: Certificate) {
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
    pub fn is_verified(&self, pub_key: &PublicKey) -> bool {
        if self.nodes.contains_key(pub_key) {
            let node = self.nodes.get(pub_key).unwrap();
            let node = self.graph.node_weight(NodeIndex::new(node.clone())).unwrap();
            return node.verified;
        }
        false
    }
    pub fn get_certified_equipments(&self) -> Vec<ChainCertification> {
        let graph = &self.graph;
        let root_node_pub_key = self.root_node_pub_key.clone();
        let nodes_to_visit: Vec<usize> = graph.node_indices()
            .map(|i| (i, graph.node_weight(i).unwrap()))
            .filter(|node| node.1.verified)
            .filter(|node| node.1.pub_key != root_node_pub_key)
            .map(|node| node.0.index())
            .collect();
        let mut paths = vec![];
        for i in nodes_to_visit {
            paths.push(self.get_certification_chain(i).unwrap());
        }
        paths
    }
    pub fn get_certification_chain(&self, i: usize) -> Option<ChainCertification> {
        let graph = &self.graph;
        let start = node_index(self.root_node);
        let goal = node_index(i);
        let mut predecessor = vec![NodeIndex::end(); graph.node_count()];
        depth_first_search(graph, Some(start), |event| {
            if let DfsEvent::TreeEdge(u, v) = event {
                predecessor[v.index()] = u;
                if v == goal {
                    return Control::Break(v);
                }
            }
            Control::Continue
        });
        let mut next = goal;
        let mut path = vec![];
        while next != start {
            let pred = predecessor[next.index()];
            let node = graph.node_weight(pred).unwrap();
            let edge_index = graph.find_edge(pred, next).unwrap();
            let edge = graph.edge_weight(edge_index).unwrap().clone();
            path.push(((node.name.clone(), node.pub_key.clone()), edge));
            next = pred;
        }
        path.reverse();
        let eq = graph.node_weight(node_index(i)).unwrap();
        Some(ChainCertification {
            name: eq.name.clone(),
            public_key: eq.pub_key.clone(),
            chain: path,
        })
    }
    pub fn add_chains(&mut self, chains: Vec<ChainCertification>) {
        for chain in chains {
            for ((issuer_name, issuer_pub_key), certificate) in chain.chain {
                let x509 = X509::from_pem(&certificate).unwrap();
                let subject_name = x509.subject_name().entries().last().unwrap().data().as_utf8().unwrap().to_string();
                let subject_pub_key = x509.public_key().unwrap().public_key_to_pem().unwrap();
                println!("add");
                self.add_certification(subject_name, subject_pub_key, issuer_name, issuer_pub_key, certificate);
            }
        }
    }
}

#[allow(dead_code)]
#[derive(Clone)]
pub struct Equipment {
    name: String,
    pub_key: PublicKey,
    pub verified: bool,
}

impl Equipment {
    pub fn new(name: String, pub_key: PublicKey) -> Equipment {
        Equipment {
            name,
            pub_key,
            verified: false,
        }
    }
    pub fn root(name: String, pub_key: PublicKey) -> Equipment {
        Equipment {
            name,
            pub_key,
            verified: true,
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
#[derive(Clone)]
pub struct ChainCertification {
    pub name: String,
    pub public_key: PublicKey,
    pub chain: Vec<((String, PublicKey), NetEdge)>,
}