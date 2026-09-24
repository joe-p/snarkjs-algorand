/* eslint-disable */
import algosdk from "algosdk";
import {
  ARC56AppClient,
  type AppClientMethodParams,
  type BareCreateParams,
  type BareExecutionResult,
  type CreateMethodParams,
  type MethodParams,
  type MethodExecutionResult,
  type PaymentParams,
  type ARC56Contract,
} from "@joe-p/algokit-lite";

type TypedMethodParams<TArgs = undefined> = Omit<
  AppClientMethodParams,
  "method" | "methodArgs"
> &
  (TArgs extends undefined ? { args?: undefined } : { args: TArgs });
type TypedCreateMethodParams<TArgs = undefined> = Omit<
  CreateMethodParams,
  "method" | "methodArgs"
> &
  (TArgs extends undefined ? { args?: undefined } : { args: TArgs });
type TypedBareCreateParams = Omit<
  BareCreateParams,
  "arc56" | "algod" | "getSuggestedParams" | "templateVariables"
>;

export const ARC56_JSON =
  '{"name":"Groth16Bn254SignalsAndProof","structs":{"Groth16Bn254Proof":[{"name":"pi_a","type":"byte[64]"},{"name":"pi_b","type":"byte[128]"},{"name":"pi_c","type":"byte[64]"}]},"methods":[{"name":"signalsAndProof","args":[{"type":"uint256[]","name":"signals"},{"type":"(byte[64],byte[128],byte[64])","struct":"Groth16Bn254Proof","name":"proof"}],"returns":{"type":"void"},"actions":{"create":[],"call":["NoOp"]},"readonly":false,"events":[],"recommendations":{}}],"arcs":[22,28],"networks":{},"state":{"schema":{"global":{"ints":0,"bytes":0},"local":{"ints":0,"bytes":0}},"keys":{"global":{},"local":{},"box":{}},"maps":{"global":{},"local":{},"box":{}}},"bareActions":{"create":["NoOp"],"call":[]},"sourceInfo":{"approval":{"sourceInfo":[{"pc":[44],"errorMessage":"invalid array length header"},{"pc":[54],"errorMessage":"invalid number of bytes for arc4.dynamic_array<arc4.uint256>"},{"pc":[63],"errorMessage":"invalid number of bytes for contracts/groth16_bn254.algo.ts::Groth16Bn254Proof"}],"pcOffsetMethod":"none"},"clear":{"sourceInfo":[],"pcOffsetMethod":"none"}},"source":{"approval":"I3ByYWdtYSB2ZXJzaW9uIDExCiNwcmFnbWEgdHlwZXRyYWNrIGZhbHNlCgovLyBAYWxnb3JhbmRmb3VuZGF0aW9uL2FsZ29yYW5kLXR5cGVzY3JpcHQvYXJjNC9pbmRleC5kLnRzOjpDb250cmFjdC5hcHByb3ZhbFByb2dyYW0oKSAtPiB1aW50NjQ6Cm1haW46CiAgICAvLyBjb250cmFjdHMvZ3JvdGgxNl9ibjI1NF92ZXJpZmllci5hbGdvLnRzOjYxCiAgICAvLyBleHBvcnQgY2xhc3MgR3JvdGgxNkJuMjU0U2lnbmFsc0FuZFByb29mIGV4dGVuZHMgQ29udHJhY3QgewogICAgdHhuIE51bUFwcEFyZ3MKICAgIGJ6IG1haW5fX19hbGdvdHNfXy5kZWZhdWx0Q3JlYXRlQDUKICAgIHB1c2hieXRlcyAweDU0NGVkMGMxIC8vIG1ldGhvZCAic2lnbmFsc0FuZFByb29mKHVpbnQyNTZbXSwoYnl0ZVs2NF0sYnl0ZVsxMjhdLGJ5dGVbNjRdKSl2b2lkIgogICAgdHhuYSBBcHBsaWNhdGlvbkFyZ3MgMAogICAgbWF0Y2ggbWFpbl9zaWduYWxzQW5kUHJvb2Zfcm91dGVAMwogICAgZXJyCgptYWluX3NpZ25hbHNBbmRQcm9vZl9yb3V0ZUAzOgogICAgLy8gY29udHJhY3RzL2dyb3RoMTZfYm4yNTRfdmVyaWZpZXIuYWxnby50czo2Mi02NQogICAgLy8gcHVibGljIHNpZ25hbHNBbmRQcm9vZigKICAgIC8vICAgc2lnbmFsczogUHVibGljU2lnbmFscywKICAgIC8vICAgcHJvb2Y6IEdyb3RoMTZCbjI1NFByb29mLAogICAgLy8gKTogdm9pZCB7fQogICAgdHhuIE9uQ29tcGxldGlvbgogICAgIQogICAgdHhuIEFwcGxpY2F0aW9uSUQKICAgICYmCiAgICBhc3NlcnQKICAgIGIgc2lnbmFsc0FuZFByb29mCgptYWluX19fYWxnb3RzX18uZGVmYXVsdENyZWF0ZUA1OgogICAgLy8gY29udHJhY3RzL2dyb3RoMTZfYm4yNTRfdmVyaWZpZXIuYWxnby50czo2MQogICAgLy8gZXhwb3J0IGNsYXNzIEdyb3RoMTZCbjI1NFNpZ25hbHNBbmRQcm9vZiBleHRlbmRzIENvbnRyYWN0IHsKICAgIHR4biBPbkNvbXBsZXRpb24KICAgICEKICAgIHR4biBBcHBsaWNhdGlvbklECiAgICAhCiAgICAmJgogICAgcmV0dXJuCgoKLy8gY29udHJhY3RzL2dyb3RoMTZfYm4yNTRfdmVyaWZpZXIuYWxnby50czo6R3JvdGgxNkJuMjU0U2lnbmFsc0FuZFByb29mLnNpZ25hbHNBbmRQcm9vZltyb3V0aW5nXSgpIC0+IHZvaWQ6CnNpZ25hbHNBbmRQcm9vZjoKICAgIC8vIGNvbnRyYWN0cy9ncm90aDE2X2JuMjU0X3ZlcmlmaWVyLmFsZ28udHM6NjItNjUKICAgIC8vIHB1YmxpYyBzaWduYWxzQW5kUHJvb2YoCiAgICAvLyAgIHNpZ25hbHM6IFB1YmxpY1NpZ25hbHMsCiAgICAvLyAgIHByb29mOiBHcm90aDE2Qm4yNTRQcm9vZiwKICAgIC8vICk6IHZvaWQge30KICAgIHR4bmEgQXBwbGljYXRpb25BcmdzIDEKICAgIGR1cAogICAgcHVzaGludCAwCiAgICBleHRyYWN0X3VpbnQxNiAvLyBvbiBlcnJvcjogaW52YWxpZCBhcnJheSBsZW5ndGggaGVhZGVyCiAgICBwdXNoaW50IDMyCiAgICAqCiAgICBwdXNoaW50IDIKICAgICsKICAgIHN3YXAKICAgIGxlbgogICAgPT0KICAgIGFzc2VydCAvLyBpbnZhbGlkIG51bWJlciBvZiBieXRlcyBmb3IgYXJjNC5keW5hbWljX2FycmF5PGFyYzQudWludDI1Nj4KICAgIHR4bmEgQXBwbGljYXRpb25BcmdzIDIKICAgIGxlbgogICAgcHVzaGludCAyNTYKICAgID09CiAgICBhc3NlcnQgLy8gaW52YWxpZCBudW1iZXIgb2YgYnl0ZXMgZm9yIGNvbnRyYWN0cy9ncm90aDE2X2JuMjU0LmFsZ28udHM6Okdyb3RoMTZCbjI1NFByb29mCiAgICBwdXNoaW50IDEKICAgIHJldHVybgo=","clear":"I3ByYWdtYSB2ZXJzaW9uIDExCiNwcmFnbWEgdHlwZXRyYWNrIGZhbHNlCgovLyBAYWxnb3JhbmRmb3VuZGF0aW9uL2FsZ29yYW5kLXR5cGVzY3JpcHQvYmFzZS1jb250cmFjdC5kLnRzOjpCYXNlQ29udHJhY3QuY2xlYXJTdGF0ZVByb2dyYW0oKSAtPiB1aW50NjQ6Cm1haW46CiAgICBwdXNoaW50IDEKICAgIHJldHVybgo="},"byteCode":{"approval":"CzEbQQAYgARUTtDBNhoAjgEAAQAxGRQxGBBEQgAIMRkUMRgUEEM2GgFJgQBZgSALgQIITBUSRDYaAhWBgAISRIEBQw==","clear":"C4EBQw=="},"compilerInfo":{"compiler":"puya","compilerVersion":{"major":5,"minor":8,"patch":0}},"events":[],"templateVariables":{}}';

/** The ARC56 contract this client was generated from */
export const APP_SPEC = JSON.parse(ARC56_JSON) as ARC56Contract;

// Aliases for non-encoded ABI values
type uint256 = bigint;

// Type definitions for ARC56 structs
export type Groth16Bn254Proof = {
  pi_a: Uint8Array;
  pi_b: Uint8Array;
  pi_c: Uint8Array;
};

export type Groth16Bn254SignalsAndProofReturnTypes = {
  signalsAndProof: void;
};

export class Groth16Bn254SignalsAndProofClient extends ARC56AppClient {
  constructor(p: {
    appId: bigint | number;
    algod: algosdk.Algodv2;
    getSuggestedParams?: () => Promise<algosdk.SuggestedParams>;
    arc56?: ARC56Contract;
  }) {
    super({ arc56: APP_SPEC, ...p });
  }

  params = {
    signalsAndProof: (
      methodParams: TypedMethodParams<{
        signals: uint256[];
        proof: Groth16Bn254Proof;
      }>,
    ): MethodParams<
      Groth16Bn254SignalsAndProofReturnTypes["signalsAndProof"]
    > => {
      return this.getParams<
        Groth16Bn254SignalsAndProofReturnTypes["signalsAndProof"]
      >({
        method: "signalsAndProof",
        ...methodParams,
        methodArgs: [methodParams.args.signals, methodParams.args.proof],
      });
    },
  };

  call = {
    signalsAndProof: async (
      methodParams: TypedMethodParams<{
        signals: uint256[];
        proof: Groth16Bn254Proof;
      }>,
    ): Promise<{
      result: MethodExecutionResult;
      returnValue: Groth16Bn254SignalsAndProofReturnTypes["signalsAndProof"];
    }> => {
      return this.methodCall({
        method: "signalsAndProof",
        ...methodParams,
        methodArgs: [methodParams.args.signals, methodParams.args.proof],
      });
    },
  };

  static create = {
    bare: async (
      params: {
        algod: algosdk.Algodv2;
        getSuggestedParams?: () => Promise<algosdk.SuggestedParams>;
      } & TypedBareCreateParams & {
          templateVariables?: Record<
            string,
            string | bigint | number | Uint8Array
          >;
        },
    ): Promise<{
      appClient: Groth16Bn254SignalsAndProofClient;
      result: BareExecutionResult;
      appId: bigint;
      appAddress: algosdk.Address;
    }> => {
      const { appId, appAddress, result } = await ARC56AppClient.bareCreate({
        arc56: APP_SPEC,
        ...params,
      });
      return {
        appClient: new Groth16Bn254SignalsAndProofClient({
          appId,
          algod: params.algod,
          getSuggestedParams: params.getSuggestedParams,
        }),
        appId,
        appAddress,
        result,
      };
    },
  };
}

export default Groth16Bn254SignalsAndProofClient;
