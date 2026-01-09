#ifndef SYMCC_SEARCHSTRATEGY_H
#define SYMCC_SEARCHSTRATEGY_H

#include "picojson.h"

class FunctionCFG {
public:
  std::string funcName;
  uint32_t funcID;
  uint32_t entryBBID;                                // 入口基本块 ID
  std::set<uint32_t> bbIDs;                          // 本函数内所有 BB ID
  std::map<uint32_t, std::set<uint32_t>> intraEdges; // 内部转移: srcBBID -> {dstBBID}
  std::map<uint32_t, std::vector<std::string>> callEdges; // 调用关系: srcBBID -> [calledFuncName]

  FunctionCFG(const std::string& name, uint32_t id)
      : funcName(name), funcID(id), entryBBID(0) {}
};

typedef std::pair<uint32_t, uint32_t> trace;
class SearchStrategy {
public:

  SearchStrategy() {
//    loadJSON();
//    computeReachable();
  }

  std::map<std::string, FunctionCFG> allCFGs;

  std::set<uint32_t> BBID;
  std::set<trace> Trace, visTrace;
  std::map<uint32_t, std::set<uint32_t>>  ICFG,  revICFG;
  std::set<uint32_t> branchNodes;
  std::map<uint32_t, std::set<uint32_t>> reachableTo, reachableBranches;

  void loadJSON(){
    const char *CFGFile = getenv("PCT_CFG_PATH");
    //llvm::errs() << "[PCT] fetch CFG in PCT_CFG_PATH : " << CFGFile << "\n";
    const std::string cfgFile(CFGFile);

    std::ifstream file(cfgFile);
    if (!file.is_open()) {
      throw std::runtime_error("Failed to open CFG JSON file: " + cfgFile);
    }
    std::stringstream buffer;
    buffer << file.rdbuf();
    std::string jsonStr = buffer.str();
    file.close();

    constructICFG(jsonStr);
  }

  void loadCFGs(const std::string &jsonStr) {
    picojson::value v;
    std::string err = picojson::parse(v, jsonStr);
    if (!err.empty())
      throw std::runtime_error("JSON parse error: " + err);
    if (!v.is<picojson::object>())
      throw std::runtime_error("Root JSON element is not an object");

    auto root = v.get<picojson::object>();
    if (root.find("functions") == root.end() ||
        !root.at("functions").is<picojson::array>())
      return;

    const auto& funcs = root.at("functions").get<picojson::array>();
    for (const auto& fval : funcs) {
      if (!fval.is<picojson::object>()) continue;
      auto fobj = fval.get<picojson::object>();

      FunctionCFG cfg("", 0);

      // func_name
      cfg.funcName  = fobj.at("func_name").get<std::string>();
      cfg.funcID    = static_cast<uint32_t>(fobj.at("func_id").get<double>());
      cfg.entryBBID = static_cast<uint32_t>(fobj.at("entry_bb_id").get<double>());

      // bb_ids
      for (auto& idval : fobj.at("bb_ids").get<picojson::array>())
        cfg.bbIDs.insert(static_cast<uint32_t>(idval.get<double>()));

      // intra_edges
      auto edges = fobj.at("intra_edges").get<picojson::object>();
      for (auto& kv : edges) {
        uint32_t src = static_cast<uint32_t>(std::stoul(kv.first));
        std::set<uint32_t> dsts;
        for (auto& d : kv.second.get<picojson::array>())
          dsts.insert(static_cast<uint32_t>(d.get<double>()));

        cfg.intraEdges[src] = dsts;
      }

      // call_edges
      auto calls = fobj.at("call_edges").get<picojson::object>();
      for (auto& kv : calls) {
        uint32_t src = static_cast<uint32_t>(std::stoul(kv.first));
        std::vector<std::string> callees;
        for (auto& c : kv.second.get<picojson::array>())
          callees.push_back(c.get<std::string>());
        cfg.callEdges[src] = callees;
      }

      allCFGs.insert({cfg.funcName, cfg});
    }
  }

  void constructICFG(const std::string &jsonStr){
    loadCFGs(jsonStr);

    // Step 1: 构建函数名 → entryBBID 映射
    std::map<std::string, uint32_t> funcNameToEntryBB;
    for (const auto& kv : allCFGs) {
      const FunctionCFG& cfg = kv.second;
      funcNameToEntryBB[cfg.funcName] = cfg.entryBBID;
    }

    // Step 2: 收集所有 BBID
    for (const auto& kv : allCFGs) {
      const FunctionCFG& cfg = kv.second;
      BBID.insert(cfg.bbIDs.begin(), cfg.bbIDs.end());

      // Step 3: 添加 intra-procedural edges（函数内部跳转）
      for (const auto& edge : cfg.intraEdges) {
        uint32_t src = edge.first;
        for (uint32_t dst : edge.second) {
          ICFG[src].insert(dst);
          revICFG[dst].insert(src);
          Trace.insert({src, dst});
        }
      }

      // Step 4: 添加 inter-procedural call edges（调用跳转）
      for (const auto& call : cfg.callEdges) {
        uint32_t srcBB = call.first;
        const std::vector<std::string>& callees = call.second;

        for (const std::string& calleeName : callees) {
          auto it = funcNameToEntryBB.find(calleeName);
          if (it != funcNameToEntryBB.end()) {
            uint32_t entryBB = it->second;

            // 添加调用边: srcBB → entryBB
            ICFG[srcBB].insert(entryBB);
            revICFG[entryBB].insert(srcBB);
            Trace.insert({srcBB, entryBB});
          }
        }
      }
    }

//    std::cerr << "[PCT] BBInfo : ";
//    for(auto BB : BBID)
//      std::cerr << " " << (int) BB;
//    std::cerr << "\n[PCT] TRInfo : ";
//    for (auto tr : Trace)
//      std::cerr << " " << tr.first << "->" << tr.second;
//    std::cerr << "\n";
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
