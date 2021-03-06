// Generated by the gRPC C++ plugin.
// If you make any local change, they will be lost.
// source: tc.proto

#include "tc.pb.h"
#include "tc.grpc.pb.h"

#include <functional>
#include <grpcpp/impl/codegen/async_stream.h>
#include <grpcpp/impl/codegen/async_unary_call.h>
#include <grpcpp/impl/codegen/channel_interface.h>
#include <grpcpp/impl/codegen/client_unary_call.h>
#include <grpcpp/impl/codegen/client_callback.h>
#include <grpcpp/impl/codegen/message_allocator.h>
#include <grpcpp/impl/codegen/method_handler.h>
#include <grpcpp/impl/codegen/rpc_service_method.h>
#include <grpcpp/impl/codegen/server_callback.h>
#include <grpcpp/impl/codegen/server_callback_handlers.h>
#include <grpcpp/impl/codegen/server_context.h>
#include <grpcpp/impl/codegen/service_type.h>
#include <grpcpp/impl/codegen/sync_stream.h>
namespace rpc {

static const char* towncrier_method_names[] = {
  "/rpc.towncrier/attest",
  "/rpc.towncrier/status",
  "/rpc.towncrier/process",
};

std::unique_ptr< towncrier::Stub> towncrier::NewStub(const std::shared_ptr< ::grpc::ChannelInterface>& channel, const ::grpc::StubOptions& options) {
  (void)options;
  std::unique_ptr< towncrier::Stub> stub(new towncrier::Stub(channel));
  return stub;
}

towncrier::Stub::Stub(const std::shared_ptr< ::grpc::ChannelInterface>& channel)
  : channel_(channel), rpcmethod_attest_(towncrier_method_names[0], ::grpc::internal::RpcMethod::NORMAL_RPC, channel)
  , rpcmethod_status_(towncrier_method_names[1], ::grpc::internal::RpcMethod::NORMAL_RPC, channel)
  , rpcmethod_process_(towncrier_method_names[2], ::grpc::internal::RpcMethod::NORMAL_RPC, channel)
  {}

::grpc::Status towncrier::Stub::attest(::grpc::ClientContext* context, const ::rpc::Empty& request, ::rpc::Attestation* response) {
  return ::grpc::internal::BlockingUnaryCall(channel_.get(), rpcmethod_attest_, context, request, response);
}

void towncrier::Stub::experimental_async::attest(::grpc::ClientContext* context, const ::rpc::Empty* request, ::rpc::Attestation* response, std::function<void(::grpc::Status)> f) {
  ::grpc_impl::internal::CallbackUnaryCall(stub_->channel_.get(), stub_->rpcmethod_attest_, context, request, response, std::move(f));
}

void towncrier::Stub::experimental_async::attest(::grpc::ClientContext* context, const ::grpc::ByteBuffer* request, ::rpc::Attestation* response, std::function<void(::grpc::Status)> f) {
  ::grpc_impl::internal::CallbackUnaryCall(stub_->channel_.get(), stub_->rpcmethod_attest_, context, request, response, std::move(f));
}

void towncrier::Stub::experimental_async::attest(::grpc::ClientContext* context, const ::rpc::Empty* request, ::rpc::Attestation* response, ::grpc::experimental::ClientUnaryReactor* reactor) {
  ::grpc_impl::internal::ClientCallbackUnaryFactory::Create(stub_->channel_.get(), stub_->rpcmethod_attest_, context, request, response, reactor);
}

void towncrier::Stub::experimental_async::attest(::grpc::ClientContext* context, const ::grpc::ByteBuffer* request, ::rpc::Attestation* response, ::grpc::experimental::ClientUnaryReactor* reactor) {
  ::grpc_impl::internal::ClientCallbackUnaryFactory::Create(stub_->channel_.get(), stub_->rpcmethod_attest_, context, request, response, reactor);
}

::grpc::ClientAsyncResponseReader< ::rpc::Attestation>* towncrier::Stub::AsyncattestRaw(::grpc::ClientContext* context, const ::rpc::Empty& request, ::grpc::CompletionQueue* cq) {
  return ::grpc_impl::internal::ClientAsyncResponseReaderFactory< ::rpc::Attestation>::Create(channel_.get(), cq, rpcmethod_attest_, context, request, true);
}

::grpc::ClientAsyncResponseReader< ::rpc::Attestation>* towncrier::Stub::PrepareAsyncattestRaw(::grpc::ClientContext* context, const ::rpc::Empty& request, ::grpc::CompletionQueue* cq) {
  return ::grpc_impl::internal::ClientAsyncResponseReaderFactory< ::rpc::Attestation>::Create(channel_.get(), cq, rpcmethod_attest_, context, request, false);
}

::grpc::Status towncrier::Stub::status(::grpc::ClientContext* context, const ::rpc::Empty& request, ::rpc::Status* response) {
  return ::grpc::internal::BlockingUnaryCall(channel_.get(), rpcmethod_status_, context, request, response);
}

void towncrier::Stub::experimental_async::status(::grpc::ClientContext* context, const ::rpc::Empty* request, ::rpc::Status* response, std::function<void(::grpc::Status)> f) {
  ::grpc_impl::internal::CallbackUnaryCall(stub_->channel_.get(), stub_->rpcmethod_status_, context, request, response, std::move(f));
}

void towncrier::Stub::experimental_async::status(::grpc::ClientContext* context, const ::grpc::ByteBuffer* request, ::rpc::Status* response, std::function<void(::grpc::Status)> f) {
  ::grpc_impl::internal::CallbackUnaryCall(stub_->channel_.get(), stub_->rpcmethod_status_, context, request, response, std::move(f));
}

void towncrier::Stub::experimental_async::status(::grpc::ClientContext* context, const ::rpc::Empty* request, ::rpc::Status* response, ::grpc::experimental::ClientUnaryReactor* reactor) {
  ::grpc_impl::internal::ClientCallbackUnaryFactory::Create(stub_->channel_.get(), stub_->rpcmethod_status_, context, request, response, reactor);
}

void towncrier::Stub::experimental_async::status(::grpc::ClientContext* context, const ::grpc::ByteBuffer* request, ::rpc::Status* response, ::grpc::experimental::ClientUnaryReactor* reactor) {
  ::grpc_impl::internal::ClientCallbackUnaryFactory::Create(stub_->channel_.get(), stub_->rpcmethod_status_, context, request, response, reactor);
}

::grpc::ClientAsyncResponseReader< ::rpc::Status>* towncrier::Stub::AsyncstatusRaw(::grpc::ClientContext* context, const ::rpc::Empty& request, ::grpc::CompletionQueue* cq) {
  return ::grpc_impl::internal::ClientAsyncResponseReaderFactory< ::rpc::Status>::Create(channel_.get(), cq, rpcmethod_status_, context, request, true);
}

::grpc::ClientAsyncResponseReader< ::rpc::Status>* towncrier::Stub::PrepareAsyncstatusRaw(::grpc::ClientContext* context, const ::rpc::Empty& request, ::grpc::CompletionQueue* cq) {
  return ::grpc_impl::internal::ClientAsyncResponseReaderFactory< ::rpc::Status>::Create(channel_.get(), cq, rpcmethod_status_, context, request, false);
}

::grpc::Status towncrier::Stub::process(::grpc::ClientContext* context, const ::rpc::Request& request, ::rpc::Response* response) {
  return ::grpc::internal::BlockingUnaryCall(channel_.get(), rpcmethod_process_, context, request, response);
}

void towncrier::Stub::experimental_async::process(::grpc::ClientContext* context, const ::rpc::Request* request, ::rpc::Response* response, std::function<void(::grpc::Status)> f) {
  ::grpc_impl::internal::CallbackUnaryCall(stub_->channel_.get(), stub_->rpcmethod_process_, context, request, response, std::move(f));
}

void towncrier::Stub::experimental_async::process(::grpc::ClientContext* context, const ::grpc::ByteBuffer* request, ::rpc::Response* response, std::function<void(::grpc::Status)> f) {
  ::grpc_impl::internal::CallbackUnaryCall(stub_->channel_.get(), stub_->rpcmethod_process_, context, request, response, std::move(f));
}

void towncrier::Stub::experimental_async::process(::grpc::ClientContext* context, const ::rpc::Request* request, ::rpc::Response* response, ::grpc::experimental::ClientUnaryReactor* reactor) {
  ::grpc_impl::internal::ClientCallbackUnaryFactory::Create(stub_->channel_.get(), stub_->rpcmethod_process_, context, request, response, reactor);
}

void towncrier::Stub::experimental_async::process(::grpc::ClientContext* context, const ::grpc::ByteBuffer* request, ::rpc::Response* response, ::grpc::experimental::ClientUnaryReactor* reactor) {
  ::grpc_impl::internal::ClientCallbackUnaryFactory::Create(stub_->channel_.get(), stub_->rpcmethod_process_, context, request, response, reactor);
}

::grpc::ClientAsyncResponseReader< ::rpc::Response>* towncrier::Stub::AsyncprocessRaw(::grpc::ClientContext* context, const ::rpc::Request& request, ::grpc::CompletionQueue* cq) {
  return ::grpc_impl::internal::ClientAsyncResponseReaderFactory< ::rpc::Response>::Create(channel_.get(), cq, rpcmethod_process_, context, request, true);
}

::grpc::ClientAsyncResponseReader< ::rpc::Response>* towncrier::Stub::PrepareAsyncprocessRaw(::grpc::ClientContext* context, const ::rpc::Request& request, ::grpc::CompletionQueue* cq) {
  return ::grpc_impl::internal::ClientAsyncResponseReaderFactory< ::rpc::Response>::Create(channel_.get(), cq, rpcmethod_process_, context, request, false);
}

towncrier::Service::Service() {
  AddMethod(new ::grpc::internal::RpcServiceMethod(
      towncrier_method_names[0],
      ::grpc::internal::RpcMethod::NORMAL_RPC,
      new ::grpc::internal::RpcMethodHandler< towncrier::Service, ::rpc::Empty, ::rpc::Attestation>(
          std::mem_fn(&towncrier::Service::attest), this)));
  AddMethod(new ::grpc::internal::RpcServiceMethod(
      towncrier_method_names[1],
      ::grpc::internal::RpcMethod::NORMAL_RPC,
      new ::grpc::internal::RpcMethodHandler< towncrier::Service, ::rpc::Empty, ::rpc::Status>(
          std::mem_fn(&towncrier::Service::status), this)));
  AddMethod(new ::grpc::internal::RpcServiceMethod(
      towncrier_method_names[2],
      ::grpc::internal::RpcMethod::NORMAL_RPC,
      new ::grpc::internal::RpcMethodHandler< towncrier::Service, ::rpc::Request, ::rpc::Response>(
          std::mem_fn(&towncrier::Service::process), this)));
}

towncrier::Service::~Service() {
}

::grpc::Status towncrier::Service::attest(::grpc::ServerContext* context, const ::rpc::Empty* request, ::rpc::Attestation* response) {
  (void) context;
  (void) request;
  (void) response;
  return ::grpc::Status(::grpc::StatusCode::UNIMPLEMENTED, "");
}

::grpc::Status towncrier::Service::status(::grpc::ServerContext* context, const ::rpc::Empty* request, ::rpc::Status* response) {
  (void) context;
  (void) request;
  (void) response;
  return ::grpc::Status(::grpc::StatusCode::UNIMPLEMENTED, "");
}

::grpc::Status towncrier::Service::process(::grpc::ServerContext* context, const ::rpc::Request* request, ::rpc::Response* response) {
  (void) context;
  (void) request;
  (void) response;
  return ::grpc::Status(::grpc::StatusCode::UNIMPLEMENTED, "");
}


}  // namespace rpc

