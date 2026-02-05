#ifndef SYMCC_SEARCHSTRATEGY_H
#define SYMCC_SEARCHSTRATEGY_H

#include "picojson.h"
#include "filesystem"

namespace fs = std::filesystem;

class FunctionCFG {
public:
  std::string funcName;
  uint32_t entryBBAddr;                              // 入口基本块 ID
  std::set<uint32_t> bbAddrs;                          // 本函数内所有 BBID
  std::map<uint32_t, std::set<uint32_t>> intraEdges; // 内部转移: srcBBAddr -> {dstBBAddr}
  std::map<uint32_t, std::vector<std::string>> callEdges; // 调用关系: srcBBAddr -> [calledFuncName]

  FunctionCFG() : funcName(""), entryBBAddr(0) {}
};


typedef std::pair<uint32_t, uint32_t> trace;
class SearchStrategy {
public:

  uint32_t g_entry = 0;
  SearchStrategy() {
    loadJSON();

    g_entry = allCFGs["main"].entryBBAddr;
    collectAllRelevantBBs();
    //computeFullDominators();
  }

  std::map<std::string, FunctionCFG> allCFGs;

  std::set<uint32_t> BBID, visBB, releBB, branchBB;
  std::set<trace> Trace;
  std::map<uint32_t, std::set<uint32_t>> ICFG, revICFG, Dominate, revDominate;

  void loadJSON(){
    const char *CFGPath = getenv("PCT_CFG_PATH");
    std::cerr << "[PCT] fetch CFG in PCT_CFG_PATH : " << CFGPath << "\n";

    std::vector<std::string> cfgFiles = getCFGFiles(CFGPath);

    for (const auto& cfgFile : cfgFiles){
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

    constructICFG();
  }

  void loadCFG(const std::string &jsonStr) {
    picojson::value v;
    std::string err = picojson::parse(v, jsonStr);
    if (!err.empty())
      throw std::runtime_error("JSON parse error: " + err);
    if (!v.is<picojson::object>())
      throw std::runtime_error("Root JSON element is not an object");

    auto fobj = v.get<picojson::object>();
    if (fobj.find("func_name") == fobj.end())
      return;

    FunctionCFG cfg;

    // func_name
    cfg.funcName  = fobj.at("func_name").get<std::string>();
    cfg.entryBBAddr = static_cast<uint32_t>(fobj.at("entry_bb_addr").get<double>());

    // bb_ids
    for (auto& idval : fobj.at("bb_addrs").get<picojson::array>())
      cfg.bbAddrs.insert(static_cast<uint32_t>(idval.get<double>()));

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

  void constructICFG(){

    // Step 1: 构建函数名 → entryBBID 映射
    std::map<std::string, uint32_t> funcNameToEntryBB;
    for (const auto& kv : allCFGs) {
      const FunctionCFG& cfg = kv.second;
      funcNameToEntryBB[cfg.funcName] = cfg.entryBBAddr;
    }

    // Step 2: 收集所有 BBID
    for (const auto& kv : allCFGs) {
      const FunctionCFG& cfg = kv.second;
      BBID.insert(cfg.bbAddrs.begin(), cfg.bbAddrs.end());

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

    // 收集所有分支基本块
    for (const auto& kv : ICFG) {
      uint32_t branchBBID = kv.first;
      if (kv.second.size() > 1) {  // 分支基本块定义
        branchBB.insert(branchBBID);
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

  // 收集从入口可达的所有节点
  void collectAllRelevantBBs() {
    std::queue<uint32_t> q;
    std::unordered_set<uint32_t> visited;

    q.push(g_entry);
    visited.insert(g_entry);
    releBB.insert(g_entry);

    while (!q.empty()) {
      uint32_t node = q.front(); q.pop();

      auto it = ICFG.find(node);
      if (it != ICFG.end()) {
        for (uint32_t succ : it->second) {
          if (visited.find(succ) == visited.end()) {
            visited.insert(succ);
            releBB.insert(succ);
            q.push(succ);
          }
        }
      }
    }
  }

  // 计算全图支配关系（标准迭代算法）
  void computeFullDominators() {
    for (uint32_t node : releBB) {
      if (node == g_entry) {
        revDominate[node] = {g_entry};  // 入口只支配自己
      } else {
        revDominate[node] = releBB;  // 初始化为全集
      }
    }

    // 2. 生成处理顺序（BFS拓扑序近似）
    std::vector<uint32_t> order = getProcessingOrder();

    // 3. 迭代计算直到收敛
    bool changed = true;
    while (changed) {
      changed = false;

      for (uint32_t node : order) {
        if (node == g_entry) continue;

        // 计算所有前驱支配集的交集
        std::set<uint32_t> intersection;
        bool firstPred = true;

        auto predIt = revICFG.find(node);
        if (predIt != revICFG.end()) {
          for (uint32_t pred : predIt->second) {
            if (releBB.find(pred) == releBB.end()) continue;

            if (firstPred) {
              intersection = revDominate[pred];
              firstPred = false;
            } else {
              std::set<uint32_t> temp;
              std::set_intersection(
                  intersection.begin(), intersection.end(),
                  revDominate[pred].begin(), revDominate[pred].end(),
                  std::inserter(temp, temp.begin())
              );
              intersection = temp;
            }
          }
        }

        // 如果没有前驱（除入口外），跳过
        if (firstPred) continue;

        // 添加当前节点
        intersection.insert(node);

        // 检查是否变化
        if (intersection != revDominate[node]) {
          revDominate[node] = intersection;
          changed = true;
        }
      }
    }

    for (const auto& it : revDominate)
      for (auto prevBBID : it.second)
        Dominate[prevBBID].insert(it.first);
  }

  // 生成处理顺序（BFS顺序）
  std::vector<uint32_t> getProcessingOrder() const {
    std::vector<uint32_t> order;
    std::queue<uint32_t> q;
    std::unordered_set<uint32_t> visited;

    q.push(g_entry);
    visited.insert(g_entry);

    while (!q.empty()) {
      uint32_t node = q.front(); q.pop();
      order.push_back(node);

      auto it = ICFG.find(node);
      if (it != ICFG.end()) {
        for (uint32_t succ : it->second) {
          if (releBB.find(succ) != releBB.end() &&
              visited.find(succ) == visited.end()) {
            visited.insert(succ);
            q.push(succ);
          }
        }
      }
    }

    return order;
  }

  // 辅助：获取从 g_entry 到 target 的所有可达基本块（正向 BFS）
  std::set<uint32_t> getReachableSubgraph(uint32_t target) {
    std::set<uint32_t> reachable;
    if (releBB.find(target) == releBB.end()) return reachable;

    std::queue<uint32_t> q;
    q.push(g_entry);
    reachable.insert(g_entry);

    while (!q.empty()) {
      uint32_t node = q.front(); q.pop();
      // 假设你有正向 ICFG: std::unordered_map<uint32_t, std::vector<uint32_t>> ICFG;
      auto it = ICFG.find(node);
      if (it != ICFG.end()) {
        for (uint32_t succ : it->second) {
          if (releBB.count(succ) && reachable.insert(succ).second) {
            if (succ != target) // 可提前终止？不，需完整子图
              q.push(succ);
          }
        }
      }
    }
    return reachable;
  }

// 按需计算 target 的支配者集合
  std::set<uint32_t> computeDominatorsFor(uint32_t target) {
    if (revDominate.find(target) != revDominate.end())
      return revDominate[target];

    // 1. 获取从入口到 target 的可达子图
    std::set<uint32_t> subgraph = getReachableSubgraph(target);
    if (subgraph.empty() || subgraph.count(target) == 0) {
      // 不可达，返回空或仅自身？
      return {target}; // 或 throw
    }

    // 2. 初始化支配集
    std::unordered_map<uint32_t, std::set<uint32_t>> dom;
    for (uint32_t node : subgraph) {
      if (node == g_entry) {
        dom[node] = {g_entry};
      } else {
        dom[node] = subgraph; // 初始化为全子图
      }
    }

    // 3. 构建子图的前驱关系（从 revICFG 提取）
    std::unordered_map<uint32_t, std::vector<uint32_t>> subPred;
    for (uint32_t node : subgraph) {
      auto it = revICFG.find(node);
      if (it != revICFG.end()) {
        for (uint32_t pred : it->second) {
          if (subgraph.count(pred)) {
            subPred[node].push_back(pred);
          }
        }
      }
    }

    // 4. 迭代直到收敛（只在子图上）
    bool changed = true;
    while (changed) {
      changed = false;
      // 遍历顺序：BFS 从入口开始（保证前驱先更新）
      std::queue<uint32_t> q;
      std::unordered_set<uint32_t> visited;
      q.push(g_entry);
      visited.insert(g_entry);

      while (!q.empty()) {
        uint32_t node = q.front(); q.pop();
        if (node == g_entry) continue;

        // 计算所有前驱支配集的交集
        std::set<uint32_t> intersection;
        bool first = true;
        for (uint32_t pred : subPred[node]) {
          if (first) {
            intersection = dom[pred];
            first = false;
          } else {
            std::set<uint32_t> temp;
            std::set_intersection(
                intersection.begin(), intersection.end(),
                dom[pred].begin(), dom[pred].end(),
                std::inserter(temp, temp.begin())
            );
            intersection = std::move(temp);
          }
        }

        if (first) continue; // 无有效前驱（不应发生）

        intersection.insert(node); // 支配集包含自身

        if (dom[node] != intersection) {
          dom[node] = std::move(intersection);
          changed = true;
        }

        // 继续 BFS
        auto succIt = ICFG.find(node);
        if (succIt != ICFG.end()) {
          for (uint32_t succ : succIt->second) {
            if (subgraph.count(succ) && visited.insert(succ).second) {
              q.push(succ);
            }
          }
        }
      }
    }
    revDominate[target] = dom[target];
    return dom[target];
  }


  bool updateVisBB(uint32_t newBB) {
    if (BBID.find(newBB) == BBID.end())
      return false;
    auto isCoverNew = visBB.insert(newBB);
    return isCoverNew.second;
  }


private:
  std::vector<std::string> getCFGFiles(const std::string& dirPath) {
    std::vector<std::string> cfgFiles;

    try {
      for (const auto& entry : fs::directory_iterator(dirPath)) {
        if (entry.is_regular_file() &&
            entry.path().extension() == ".cfg") {
          cfgFiles.push_back(entry.path().string());
        }
      }
    } catch (const fs::filesystem_error& ex) {
      std::cerr << "Error accessing directory: " << ex.what() << '\n';
    }

    return cfgFiles;
  }

};

#endif // SYMCC_SEARCHSTRATEGY_H
