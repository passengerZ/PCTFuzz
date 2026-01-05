#ifndef SYMCC_SEARCHSTRATEGY_H
#define SYMCC_SEARCHSTRATEGY_H

#include "picojson.h"

typedef std::pair<uint32_t, uint32_t> trace;
class SearchStrategy {
public:

  SearchStrategy() {
    loadJSON();
    computeReachable();
  }

  uint32_t rootBB = 0;
  std::set<uint32_t> BBID;
  std::set<trace> Trace, visTrace;
  std::map<uint32_t, std::set<uint32_t>>  ICFG,  revICFG;
  std::set<uint32_t> branchNodes;
  std::map<uint32_t, std::set<uint32_t>> reachableTo, reachableBranches;

  void loadJSON(){
    const char *CFGFile = getenv("PCT_CFG_PATH");
    llvm::errs() << "[PCT] fetch CFG in PCT_CFG_PATH : " << CFGFile << "\n";
    const std::string cfgFile(CFGFile);

    std::ifstream file(cfgFile);
    if (!file.is_open()) {
      throw std::runtime_error("Failed to open CFG JSON file: " + cfgFile);
    }
    std::stringstream buffer;
    buffer << file.rdbuf();
    std::string jsonStr = buffer.str();
    file.close();

    loadCFG(jsonStr);
  }

  void loadCFG(const std::string &jsonStr){
    picojson::value v;
    std::string err = picojson::parse(v, jsonStr);
    if (!err.empty())
      throw std::runtime_error("JSON parse error: " + err);
    if (!v.is<picojson::object>())
      throw std::runtime_error("Root JSON element is not an object");

    const picojson::object& root = v.get<picojson::object>();

    auto rootIt = root.find("ROOT");
    if (rootIt != root.end() && rootIt->second.is<double>()){
      rootBB = static_cast<uint32_t>(rootIt->second.get<double>());
    }
    std::cerr << "[PCT] RootBB : " << rootBB << "\n";

    std::cerr << "[PCT] BBInfo : ";
    auto bbInfoIt = root.find("BBInfo");
    const picojson::array& bbArray = bbInfoIt->second.get<picojson::array>();
    for (const auto& elem : bbArray) {
      double val = elem.get<double>();
      if (val >= 0 && val <= static_cast<double>(UINT32_MAX)) {
        BBID.insert(static_cast<uint32_t>(val));
        std::cerr << " " << (int)val;
      }
    }

    std::cerr << "\n[PCT] TRInfo : ";
    auto trInfoIt = root.find("TRInfo");
    const picojson::object& trObj = trInfoIt->second.get<picojson::object>();
    for (const auto& kv : trObj) {
      const std::string& srcStr     = kv.first;
      const picojson::value& dstVal = kv.second;

      uint32_t srcID;
      try {
        srcID = static_cast<uint32_t>(std::stoul(srcStr));
      } catch (...) {
        continue;
      }

      const picojson::array& dstArray = dstVal.get<picojson::array>();
      for (const auto& dstElem : dstArray) {
        double d = dstElem.get<double>();
        if (d >= 0 && d <= static_cast<double>(UINT32_MAX)) {
          uint32_t dstID = static_cast<uint32_t>(d);
          Trace.insert(std::make_pair(srcID, dstID));
          std::cerr << " " << (int)srcID << "->" << dstID << ",";

          ICFG[srcID].insert(dstID);
          revICFG[dstID].insert(srcID);
        }
      }
    }
    std::cerr << "\n";
  }

  void computeReachable(){
    // compute all the branch BB
    for (uint32_t bb : BBID) {
      if (ICFG.count(bb) && ICFG[bb].size() > 1) {
        branchNodes.insert(bb);
      }
    }

    // compute the normal reachable BB
    for (uint32_t bb : BBID) {
      std::set<uint32_t> visited;
      std::queue<uint32_t> q;

      q.push(bb);
      visited.insert(bb);

      while (!q.empty()) {
        uint32_t cur = q.front(); q.pop();

        if (revICFG.find(cur) != revICFG.end()) {
          for (uint32_t pred : revICFG.at(cur)) {
            if (visited.find(pred) == visited.end()) {
              visited.insert(pred);
              q.push(pred);
            }
          }
        }
      }

      std::set<uint32_t> reachedBranches;
      for (auto node : visited){
        if (branchNodes.count(node))
          reachedBranches.insert(node);
      }

      reachableTo[bb] = std::move(visited);
      reachableBranches[bb] = std::move(reachedBranches);
    }
  }

  bool updateCovTrace(trace& newVis) {
    auto isCoverNew = visTrace.insert(newVis);
    return isCoverNew.second;
  }

  void pruneRedundantUncoveredEdges(
      std::map<trace, std::set<trace>>& UnvisRelativeBranches) {

    std::vector<std::pair<trace,std::set<trace>>>
        edges(UnvisRelativeBranches.begin(), UnvisRelativeBranches.end());

    // 按 critical trace 大小升序排列：小的（更浅的）优先保留
    std::sort(edges.begin(), edges.end(),
              [](const auto& a, const auto& b) {
                return a.second.size() < b.second.size(); // 小集合在前
              });

    std::set<std::pair<uint32_t, uint32_t>> toErase;

    for (size_t i = 0; i < edges.size(); ++i) {
      const auto& [edge_i, trace_i] = edges[i];
      if (toErase.count(edge_i)) continue;

      for (size_t j = i + 1; j < edges.size(); ++j) {
        const auto& [edge_j, trace_j] = edges[j];
        if (toErase.count(edge_j)) continue;

        // 如果 trace_i 是 trace_j 的子集，则 edge_j 是更深的边，可删除
        if (trace_i.size() <= trace_j.size()) {
          bool isSubset = true;
          for (const auto& trans : trace_i) {
            if (trace_j.find(trans) == trace_j.end()) {
              isSubset = false;
              break;
            }
          }
          if (isSubset) {
            toErase.insert(edge_j);
          }
        }
      }
    }

    for (const auto& e : toErase)
      UnvisRelativeBranches.erase(e);
  }

  std::map<trace, std::set<trace>> recomputeGuidance() {
//    std::cerr << "[zgf dbg] curr visEdge : ";
//    for (auto edge : visTrace)
//      std::cerr << edge.first << "->" << edge.second << ", ";
//    std::cerr << "\n";

    // (1) find the uncovered trace(u->v)
    std::set<trace> unvisTrace;
    std::set_difference(
        Trace.begin(), Trace.end(),
        visTrace.begin(), visTrace.end(),
        std::inserter(unvisTrace, unvisTrace.begin())
    );

    std::map<trace, std::set<trace>> UnvisRelativeBranches;
    for (auto& edge : unvisTrace) {
      uint32_t u = edge.first;
      auto& reachBB = reachableTo[u];
      auto& reachBranches = reachableBranches[u]; // 能到达 u 的 branch节点

      if (reachBranches.empty())
        continue;

      std::set<trace> towardTrace, tempTrace;
      for (uint32_t branchNode : reachBranches) {
        if (branchNode == u){
          towardTrace.insert(std::make_pair(edge.first, edge.second));
          continue;
        }

        const auto& succs = ICFG[branchNode];
        tempTrace.clear();

        for (uint32_t succ : succs)
          if (reachBB.count(succ))
            tempTrace.insert(std::make_pair(branchNode, succ));

        if (tempTrace.size() == 1) {
          towardTrace.insert(tempTrace.begin(), tempTrace.end());
        }
      }
      UnvisRelativeBranches[edge] = towardTrace;
    }

    // merge multiple targets
    pruneRedundantUncoveredEdges(UnvisRelativeBranches);

//    for (auto& it : UnvisRelativeBranches) {
//      auto edge = it.first;
//      auto traces = it.second;
//      std::cerr << "[zgf dbg] uncovered : " << edge.first << "->" << edge.second << "\n";
//      std::cerr << "relative trace : ";
//      for (auto relaEdge : traces)
//        std::cerr << relaEdge.first << "->" << relaEdge.second << " ";
//      std::cerr << "\n";
//    }

    return UnvisRelativeBranches;
  }
};

#endif // SYMCC_SEARCHSTRATEGY_H
