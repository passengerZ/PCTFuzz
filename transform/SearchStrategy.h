#ifndef SYMCC_SEARCHSTRATEGY_H
#define SYMCC_SEARCHSTRATEGY_H

#include "picojson.h"
#include "filesystem"

namespace fs = std::filesystem;

class FunctionCFG {
public:
  std::string funcName;
  uint64_t entryBBAddr;                              // 入口基本块 ID
  std::set<uint64_t> bbAddrs;                          // 本函数内所有 BB ID
  std::map<uint64_t, std::set<uint32_t>> intraEdges; // 内部转移: srcBBAddr -> {dstBBAddr}
  std::map<uint64_t, std::vector<std::string>> callEdges; // 调用关系: srcBBAddr -> [calledFuncName]

  FunctionCFG(const std::string& name)
      : funcName(name), entryBBAddr(0) {}
};


typedef std::pair<uint32_t, uint32_t> trace;
class SearchStrategy {
public:

  SearchStrategy() {
    loadJSON();
    //computeReachable();
  }

  std::map<std::string, FunctionCFG> allCFGs;

  std::set<uint32_t> BBID, visBB;
  std::set<trace> Trace;
  std::map<uint32_t, std::set<uint32_t>>  ICFG,  revICFG;

  void loadJSON(){
    const char *CFGPath = getenv("PCT_CFG_PATH");
    std::cerr << "[PCT] fetch CFG in PCT_CFG_PATH : " << CFGPath << "\n";

    std::vector<std::string> cfgFiles = getCFGFiles(CFGPath);

    for (auto cfgFile : cfgFiles){
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

    FunctionCFG cfg("");

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

//    std::cerr << "[PCT] BBInfo : ";
//    for(auto BB : BBID)
//      std::cerr << " " << (int) BB;
//    std::cerr << "\n[PCT] TRInfo : ";
//    for (auto tr : Trace)
//      std::cerr << " " << tr.first << "->" << tr.second;
//    std::cerr << "\n";
  }


  bool updateVisBB(uint32_t newBB) {
    if (BBID.find(newBB) == BBID.end())
      return false;
    auto isCoverNew = visBB.insert(newBB);

    return isCoverNew.second;
  }

  std::set<uint32_t> computeDeadBB() {
    std::set<uint32_t> deadBB;

    // Step 1: 计算未覆盖块
    std::set<uint32_t> uncovered;
    std::set_difference(BBID.begin(), BBID.end(),
                        visBB.begin(), visBB.end(),
                        std::inserter(uncovered, uncovered.begin()));

    // 如果没有未覆盖块，则所有已覆盖块都无法到达“未覆盖块”（因为不存在）
    if (uncovered.empty()) {
      return deadBB;
    }

    // Step 2: 反向 BFS —— 从所有 uncovered 块出发，在 revICFG 上遍历
    std::unordered_set<uint32_t> canReachUncovered; // 使用 unordered_set 加速查找
    std::queue<uint32_t> q;

    // 初始化队列：所有 uncovered 块
    for (uint32_t bb : uncovered) {
      canReachUncovered.insert(bb);
      q.push(bb);
    }

    // BFS
    while (!q.empty()) {
      uint32_t current = q.front();
      q.pop();

      // 遍历 current 在反向图中的前驱（即原图中能跳到 current 的节点）
      auto it = revICFG.find(current);
      if (it != revICFG.end()) {
        for (uint32_t pred : it->second) {
          // 如果前驱还没被访问过，加入队列
          if (canReachUncovered.insert(pred).second) {
            q.push(pred);
          }
        }
      }
    }

    // Step 3: deadBB = visitedBB - canReachUncovered
    for (uint32_t bb : visBB) {
      if (ICFG[bb].size() < 2) continue;
      if (canReachUncovered.find(bb) == canReachUncovered.end()) {
        deadBB.insert(bb);
      }
    }

    return deadBB;
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
