#ifndef TOWN_CRIER_RPC_H
#define TOWN_CRIER_RPC_H

#include "services/generated/tc.grpc.pb.h"
#include "services/generated/tc.pb.h"

#include <sgx_eid.h>

#include <log4cxx/logger.h>
#include <log4cxx/log4cxx.h>
#include <string>

#include "Common/Constants.h"
#include <grpc/grpc.h>

class RpcServer final: public rpc::towncrier::Service {
 private:
    log4cxx::LoggerPtr logger;
    sgx_enclave_id_t eid;
    // (DCMMC) 记录下当前 tc server 工作的 ip 和 端口
    std::string tc_ip_port;
    // TX_BUF_SIZE is defined in Constants.h
    uint8_t resp_buffer[TX_BUF_SIZE] = {0};
  public:
    RpcServer(sgx_enclave_id_t eid, std::string& tc_ip_port): logger( log4cxx::Logger::getLogger("RPC")), eid(eid), tc_ip_port(tc_ip_port) {
    }

   ::grpc::Status attest(::grpc::ServerContext* context,
                         const ::rpc::Empty* request,
                         ::rpc::Attestation* response) override;
   ::grpc::Status status(::grpc::ServerContext* context,
                         const ::rpc::Empty* request,
                         ::rpc::Status* response) override;
   ::grpc::Status process(::grpc::ServerContext* context,
                          const ::rpc::Request* request,
                          ::rpc::Response* response) override;
 };

#endif  // TOWN_CRIER_RPC_H
