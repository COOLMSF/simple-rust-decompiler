use std::collections::{HashMap, HashSet, VecDeque};

use crate::ir::IrFunction;

/// Control-flow graph
#[derive(Debug)]
pub struct Cfg {
    /// block id → list of successor ids
    pub succs: HashMap<u32, Vec<u32>>,
    /// block id → list of predecessor ids
    pub preds: HashMap<u32, Vec<u32>>,
    pub entry: u32,
    pub block_ids: Vec<u32>,
}

impl Cfg {
    pub fn build(func: &IrFunction) -> Self {
        let mut succs: HashMap<u32, Vec<u32>> = HashMap::new();
        let mut preds: HashMap<u32, Vec<u32>> = HashMap::new();
        let mut block_ids = Vec::new();

        for block in &func.blocks {
            block_ids.push(block.id);
            succs.entry(block.id).or_default();
            preds.entry(block.id).or_default();
        }

        for block in &func.blocks {
            for s in block.successors() {
                succs.entry(block.id).or_default().push(s);
                preds.entry(s).or_default().push(block.id);
            }
        }

        let entry = func.blocks.first().map(|b| b.id).unwrap_or(0);
        Self { succs, preds, entry, block_ids }
    }

    pub fn successors(&self, id: u32) -> &[u32] {
        self.succs.get(&id).map(|v| v.as_slice()).unwrap_or(&[])
    }

    pub fn predecessors(&self, id: u32) -> &[u32] {
        self.preds.get(&id).map(|v| v.as_slice()).unwrap_or(&[])
    }
}

/// Dominator tree using the Cooper-Harvey-Kennedy algorithm (simple iterative)
#[derive(Debug)]
pub struct DomTree {
    /// block id → immediate dominator (None for entry)
    pub idom: HashMap<u32, Option<u32>>,
    /// Reverse post-order of blocks
    pub rpo: Vec<u32>,
    /// RPO index of each block
    pub rpo_idx: HashMap<u32, usize>,
}

impl DomTree {
    pub fn compute(cfg: &Cfg) -> Self {
        // Compute RPO via DFS
        let mut visited = HashSet::new();
        let mut rpo = Vec::new();
        let mut stack = vec![(cfg.entry, false)];
        while let Some((id, done)) = stack.last().cloned() {
            stack.pop();
            if done {
                rpo.push(id);
                continue;
            }
            if visited.contains(&id) {
                continue;
            }
            visited.insert(id);
            stack.push((id, true));
            for &s in cfg.successors(id) {
                if !visited.contains(&s) {
                    stack.push((s, false));
                }
            }
        }
        rpo.reverse();

        let mut rpo_idx: HashMap<u32, usize> = HashMap::new();
        for (i, &id) in rpo.iter().enumerate() {
            rpo_idx.insert(id, i);
        }

        // Cooper et al. iterative dominator algorithm
        let mut idom: HashMap<u32, Option<u32>> = HashMap::new();
        for &id in &rpo {
            idom.insert(id, None);
        }
        if let Some(&entry) = rpo.first() {
            idom.insert(entry, Some(entry));
        }

        let intersect = |b1: u32, b2: u32, idom: &HashMap<u32, Option<u32>>, rpo_idx: &HashMap<u32, usize>| -> u32 {
            let mut finger1 = b1;
            let mut finger2 = b2;
            while finger1 != finger2 {
                while rpo_idx[&finger1] > rpo_idx[&finger2] {
                    finger1 = idom[&finger1].unwrap_or(finger1);
                }
                while rpo_idx[&finger2] > rpo_idx[&finger1] {
                    finger2 = idom[&finger2].unwrap_or(finger2);
                }
            }
            finger1
        };

        let mut changed = true;
        while changed {
            changed = false;
            for &b in rpo.iter().skip(1) {
                let preds = cfg.predecessors(b);
                let processed_preds: Vec<u32> = preds
                    .iter()
                    .copied()
                    .filter(|&p| idom.get(&p).and_then(|x| *x).is_some())
                    .collect();
                if processed_preds.is_empty() {
                    continue;
                }
                let new_idom = processed_preds
                    .iter()
                    .skip(1)
                    .fold(processed_preds[0], |acc, &p| {
                        intersect(acc, p, &idom, &rpo_idx)
                    });
                let new_val = if new_idom == b { None } else { Some(new_idom) };
                if idom[&b] != new_val {
                    idom.insert(b, new_val);
                    changed = true;
                }
            }
        }

        Self { idom, rpo, rpo_idx }
    }

    /// Does `a` dominate `b`?
    pub fn dominates(&self, a: u32, b: u32) -> bool {
        if a == b {
            return true;
        }
        let mut cur = b;
        loop {
            match self.idom.get(&cur).and_then(|x| *x) {
                None => return false,
                Some(p) if p == a => return true,
                Some(p) if p == cur => return false,
                Some(p) => cur = p,
            }
        }
    }

    pub fn children(&self, id: u32) -> Vec<u32> {
        self.idom
            .iter()
            .filter_map(|(&b, &dom)| {
                if dom == Some(id) && b != id {
                    Some(b)
                } else {
                    None
                }
            })
            .collect()
    }
}

/// Loop information
#[derive(Debug, Clone)]
pub struct LoopInfo {
    /// header → set of blocks in this loop
    pub loops: HashMap<u32, HashSet<u32>>,
    /// block → innermost loop header
    pub block_loop: HashMap<u32, u32>,
    /// Back edges: (tail, header)
    pub back_edges: Vec<(u32, u32)>,
}

impl LoopInfo {
    pub fn compute(cfg: &Cfg, dom: &DomTree) -> Self {
        let mut back_edges = Vec::new();
        // A back edge is (src, tgt) where tgt dominates src
        for &src in &cfg.block_ids {
            for &tgt in cfg.successors(src) {
                if dom.dominates(tgt, src) {
                    back_edges.push((src, tgt));
                }
            }
        }

        let mut loops: HashMap<u32, HashSet<u32>> = HashMap::new();
        for &(tail, header) in &back_edges {
            let entry = loops.entry(header).or_default();
            entry.insert(header);
            // BFS backwards from tail to header
            let mut queue = VecDeque::new();
            queue.push_back(tail);
            while let Some(b) = queue.pop_front() {
                if entry.contains(&b) {
                    continue;
                }
                entry.insert(b);
                for &p in cfg.predecessors(b) {
                    if !entry.contains(&p) {
                        queue.push_back(p);
                    }
                }
            }
        }

        let mut block_loop: HashMap<u32, u32> = HashMap::new();
        for (&header, members) in &loops {
            for &b in members {
                block_loop.entry(b).or_insert(header);
                // prefer innermost loop (smaller set)
                if let Some(&cur_hdr) = block_loop.get(&b) {
                    if loops.contains_key(&cur_hdr) {
                        let cur_sz = loops[&cur_hdr].len();
                        let new_sz = loops[&header].len();
                        if new_sz < cur_sz {
                            block_loop.insert(b, header);
                        }
                    }
                }
            }
        }

        Self { loops, block_loop, back_edges }
    }

    pub fn is_loop_header(&self, id: u32) -> bool {
        self.loops.contains_key(&id)
    }

    pub fn is_back_edge(&self, src: u32, dst: u32) -> bool {
        self.back_edges.contains(&(src, dst))
    }

    /// Get loop exit blocks (blocks inside loop with successors outside)
    pub fn loop_exits(&self, header: u32, cfg: &Cfg) -> Vec<u32> {
        if let Some(members) = self.loops.get(&header) {
            members
                .iter()
                .filter(|&&b| {
                    cfg.successors(b).iter().any(|&s| !members.contains(&s))
                })
                .copied()
                .collect()
        } else {
            vec![]
        }
    }
}

/// Full analysis result for a function
#[derive(Debug)]
pub struct FunctionAnalysis {
    pub cfg: Cfg,
    pub dom: DomTree,
    pub loops: LoopInfo,
}

impl FunctionAnalysis {
    pub fn analyze(func: &IrFunction) -> Self {
        let cfg = Cfg::build(func);
        let dom = DomTree::compute(&cfg);
        let loops = LoopInfo::compute(&cfg, &dom);
        Self { cfg, dom, loops }
    }
}
