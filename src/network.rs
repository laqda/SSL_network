use petgraph::{Graph, Directed};
use petgraph::graph::{node_index, NodeIndex};
use petgraph::visit::{depth_first_search, DfsEvent, Control};
use crate::certification::{Certificate, Equipment, CertificationChain};
use crate::errors::{ResultSSL, SSLNetworkError};

type NetworkNode = Equipment;
type NetworkEdge = Certificate;
type NetworkGraph = Graph<NetworkNode, NetworkEdge, Directed>;

pub trait Network {
    fn new(root: &Equipment) -> Self;
    fn add_equipment(&mut self, equipment: &Equipment) -> usize;
    fn add_certificate(&mut self, certificate: &Certificate) -> ResultSSL<()>;
    fn contains(&self, equipment: &Equipment) -> bool;
    fn is_equipment_certified(&self, equipment: &Equipment) -> ResultSSL<bool>;
    fn is_equipment_directly_certified(&self, equipment: &Equipment) -> ResultSSL<bool>;
    fn get_chain_certifications(&self, equipment: &Equipment) -> ResultSSL<CertificationChain>;
    fn get_chains_certifications(&self) -> ResultSSL<Vec<CertificationChain>>;
    fn add_chains_certifications(&mut self, chains: Vec<CertificationChain>) -> ResultSSL<()>;
}

pub struct EquipmentNetwork {
    root_index: usize,
    graph: NetworkGraph,
}

impl Network for EquipmentNetwork {
    fn new(root_eq: &Equipment) -> EquipmentNetwork {
        let mut graph = NetworkGraph::new();
        let root_index = graph.add_node(root_eq.clone()).index();
        EquipmentNetwork {
            root_index,
            graph,
        }
    }
    fn add_equipment(&mut self, equipment: &Equipment) -> usize {
        self.graph.add_node(equipment.clone()).index()
    }
    fn add_certificate(&mut self, certificate: &Certificate) -> ResultSSL<()> {
        if !self.contains(certificate.subject()) {
            self.add_equipment(certificate.subject());
        }
        if !self.contains(certificate.issuer()) {
            self.add_equipment(certificate.issuer());
        }
        let subject_index = self.get_node_index(certificate.subject()).ok_or(SSLNetworkError::EquipmentNotFound {})?;
        let issuer_index = self.get_node_index(certificate.issuer()).ok_or(SSLNetworkError::EquipmentNotFound {})?;
        self.graph.add_edge(node_index(issuer_index), node_index(subject_index), certificate.clone());
        Ok(())
    }
    fn contains(&self, equipment: &Equipment) -> bool {
        match self.get_node_index(equipment) {
            Some(_) => true,
            None => false,
        }
    }
    fn is_equipment_certified(&self, equipment: &Equipment) -> ResultSSL<bool> {
        let chain = match self.get_chain_certifications(equipment) {
            Ok(chain) => chain,
            Err(SSLNetworkError::CertificateNotFound {}) => return Ok(false),
            Err(SSLNetworkError::EquipmentNotFound {}) => return Ok(false),
            Err(e) => return Err(e),
        };
        chain.is_valid()
    }
    fn is_equipment_directly_certified(&self, equipment: &Equipment) -> ResultSSL<bool> {
        let chain = match self.get_chain_certifications(equipment) {
            Ok(chain) => chain,
            Err(SSLNetworkError::CertificateNotFound {}) => return Ok(false),
            Err(SSLNetworkError::EquipmentNotFound {}) => return Ok(false),
            Err(e) => return Err(e),
        };
        if chain.0.len() != 1 {
            return Ok(false);
        }
        chain.is_valid()
    }
    fn get_chain_certifications(&self, equipment: &Equipment) -> ResultSSL<CertificationChain> {
        let root_index = node_index(self.root_index);
        let goal_index = match self.get_node_index(equipment) {
            Some(i) => i,
            None => return Err(SSLNetworkError::EquipmentNotFound {}),
        };
        let goal_index = node_index(goal_index);
        let mut predecessor = vec![NodeIndex::end(); self.graph.node_count()];
        depth_first_search(&self.graph, Some(root_index), |event| {
            if let DfsEvent::TreeEdge(u, v) = event {
                predecessor[v.index()] = u;
                if v == goal_index {
                    return Control::Break(v);
                }
            }
            Control::Continue
        });
        let mut node = goal_index;
        let mut chain = vec![];
        while node != root_index {
            let pred = predecessor[node.index()];
            let certificate_index = match self.graph.find_edge(pred, node) {
                Some(index) => index,
                None => return Err(SSLNetworkError::CertificateNotFound {})
            };
            let certificate = match self.graph.edge_weight(certificate_index) {
                Some(certificate) => certificate,
                None => return Err(SSLNetworkError::CertificateNotFound {})
            };
            chain.push(certificate.clone());
            node = pred;
        }
        chain.reverse();
        Ok((CertificationChain)(chain))
    }

    fn get_chains_certifications(&self) -> ResultSSL<Vec<CertificationChain>> {
        let mut chains = vec![];
        for node in self.graph.raw_nodes() {
            let chain = match self.get_chain_certifications(&node.weight) {
                Ok(chain) => chain,
                Err(SSLNetworkError::CertificateNotFound {}) => continue, // no certification chain to that specific equipment
                Err(e) => return Err(e),
            };
            chains.push(chain);
        }
        Ok(chains)
    }

    fn add_chains_certifications(&mut self, chains: Vec<CertificationChain>) -> ResultSSL<()> {
        for chain in chains {
            for certificate in chain.get_certificates() {
                self.add_certificate(certificate)?;
            }
        }
        Ok(())
    }
}

impl EquipmentNetwork {
    fn get_node_index(&self, equipment: &Equipment) -> Option<usize> {
        for node_index in self.graph.node_indices() {
            let current_equipment = match self.graph.node_weight(node_index) {
                Some(current_equipment) => current_equipment,
                None => continue,
            };
            if equipment == current_equipment {
                return Some(node_index.index());
            }
        }
        None
    }
}
