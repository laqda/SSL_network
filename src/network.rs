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
    fn add_certificates(&mut self, certificates: Vec<Certificate>) -> ResultSSL<()>;
    fn contains(&self, equipment: &Equipment) -> bool;
    fn is_equipment_certified(&self, equipment: &Equipment) -> ResultSSL<bool>;
    fn is_equipment_directly_certified(&self, equipment: &Equipment) -> ResultSSL<bool>;
    fn get_chain_certifications_to_root(&self, equipment: &Equipment) -> ResultSSL<Option<CertificationChain>>;
    fn get_chain_certifications_from_root(&self, equipment: &Equipment) -> ResultSSL<Option<CertificationChain>>;
    fn get_all_chains_certifications_from_root(&self) -> ResultSSL<Vec<CertificationChain>>;
    fn get_knowledge(&self) -> ResultSSL<Vec<Certificate>>;
    fn add_chain_certifications(&mut self, chain: CertificationChain) -> ResultSSL<()>;
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

    fn add_certificates(&mut self, certificates: Vec<Certificate>) -> ResultSSL<()> {
        for certificate in certificates {
            self.add_certificate(&certificate)?;
        }
        Ok(())
    }

    fn contains(&self, equipment: &Equipment) -> bool {
        match self.get_node_index(equipment) {
            Some(_) => true,
            None => false,
        }
    }
    fn is_equipment_certified(&self, equipment: &Equipment) -> ResultSSL<bool> {
        let chain = match self.get_chain_certifications_from_root(equipment) {
            Ok(chain) => chain,
            Err(SSLNetworkError::CertificateNotFound {}) => return Ok(false),
            Err(SSLNetworkError::EquipmentNotFound {}) => return Ok(false),
            Err(e) => return Err(e),
        };
        match chain {
            Some(chain) => chain.is_valid(),
            None => Ok(false),
        }
    }
    fn is_equipment_directly_certified(&self, equipment: &Equipment) -> ResultSSL<bool> {
        let chain = match self.get_chain_certifications_from_root(equipment) {
            Ok(chain) => chain,
            Err(SSLNetworkError::CertificateNotFound {}) => return Ok(false),
            Err(SSLNetworkError::EquipmentNotFound {}) => return Ok(false),
            Err(e) => return Err(e),
        };
        let chain = match chain {
            Some(chain) => chain,
            None => return Ok(false),
        };
        if chain.0.len() != 1 {
            return Ok(false);
        }
        chain.is_valid()
    }

    fn get_chain_certifications_to_root(&self, equipment: &Equipment) -> ResultSSL<Option<CertificationChain>> {
        Ok(match self.get_node_index(equipment) {
            Some(i) => Some(self.get_chain_certifications(self.root_index, i)?),
            None => None,
        })
    }

    fn get_chain_certifications_from_root(&self, equipment: &Equipment) -> ResultSSL<Option<CertificationChain>> {
        Ok(match self.get_node_index(equipment) {
            Some(i) => Some(self.get_chain_certifications(i, self.root_index)?),
            None => None,
        })
    }

    fn get_all_chains_certifications_from_root(&self) -> ResultSSL<Vec<CertificationChain>> {
        let mut chains = vec![];
        for node in self.graph.raw_nodes() {
            let chain = match self.get_chain_certifications_from_root(&node.weight) {
                Ok(chain) => chain,
                Err(SSLNetworkError::CertificateNotFound {}) => continue, // no certification chain to that specific equipment
                Err(e) => return Err(e),
            };
            if let Some(chain) = chain {
                chains.push(chain);
            }
        }
        Ok(chains)
    }

    fn get_knowledge(&self) -> ResultSSL<Vec<Certificate>> {
        let mut certificates = vec![];
        for certifier in self.graph.node_indices() {
            for certified in self.graph.node_indices() {
                if certifier != certified {
                    let certificate_index = match self.graph.find_edge(certifier, certified) {
                        Some(index) => index,
                        None => continue,
                    };
                    let certificate = match self.graph.edge_weight(certificate_index) {
                        Some(certificate) => certificate,
                        None => continue,
                    };
                    certificates.push(certificate.clone());
                }
            }
        }
        Ok(certificates)
    }

    fn add_chain_certifications(&mut self, chain: CertificationChain) -> ResultSSL<()> {
        for certificate in chain.get_certificates() {
            self.add_certificate(certificate)?;
        }
        Ok(())
    }

    fn add_chains_certifications(&mut self, chains: Vec<CertificationChain>) -> ResultSSL<()> {
        for chain in chains {
            self.add_chain_certifications(chain)?;
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
    fn get_chain_certifications(&self, certified: usize, certifier: usize) -> ResultSSL<CertificationChain> {
        let root_index = node_index(certifier);
        let goal_index = node_index(certified);
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
}
