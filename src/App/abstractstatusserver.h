/**
 * This file is generated by jsonrpcstub, DO NOT CHANGE IT MANUALLY!
 */

#ifndef JSONRPC_CPP_STUB_ABSTRACTSTATUSSERVER_H_
#define JSONRPC_CPP_STUB_ABSTRACTSTATUSSERVER_H_

#include <jsonrpccpp/server.h>

class AbstractStatusServer : public jsonrpc::AbstractServer<AbstractStatusServer>
{
    public:
        AbstractStatusServer(jsonrpc::AbstractServerConnector &conn, jsonrpc::serverVersion_t type = jsonrpc::JSONRPC_SERVER_V2) : jsonrpc::AbstractServer<AbstractStatusServer>(conn, type)
        {
            this->bindAndAddMethod(jsonrpc::Procedure("attest", jsonrpc::PARAMS_BY_NAME, jsonrpc::JSON_OBJECT,  NULL), &AbstractStatusServer::attestI);
            this->bindAndAddMethod(jsonrpc::Procedure("status", jsonrpc::PARAMS_BY_NAME, jsonrpc::JSON_OBJECT,  NULL), &AbstractStatusServer::statusI);
            this->bindAndAddMethod(jsonrpc::Procedure("process", jsonrpc::PARAMS_BY_NAME, jsonrpc::JSON_OBJECT, "data",jsonrpc::JSON_STRING,"nonce",jsonrpc::JSON_INTEGER,"txid",jsonrpc::JSON_STRING, NULL), &AbstractStatusServer::processI);
        }

        inline virtual void attestI(const Json::Value &request, Json::Value &response)
        {
            (void)request;
            response = this->attest();
        }
        inline virtual void statusI(const Json::Value &request, Json::Value &response)
        {
            (void)request;
            response = this->status();
        }
        inline virtual void processI(const Json::Value &request, Json::Value &response)
        {
            response = this->process(request["data"].asString(), request["nonce"].asInt(), request["txid"].asString());
        }
        virtual Json::Value attest() = 0;
        virtual Json::Value status() = 0;
        virtual Json::Value process(const std::string& data, int nonce, const std::string& txid) = 0;
};

#endif //JSONRPC_CPP_STUB_ABSTRACTSTATUSSERVER_H_
