import algosdk from "algosdk";
import {
  ARC56AppClient,
  type AppClientMethodParams,
  type BareCreateParams,
  type BareExecutionResult,
  type CreateMethodParams,
  type MethodParams,
  type MethodExecutionResult,
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
  '{"name":"PlonkSignalsAndProof","structs":{"PlonkProof":[{"name":"A","type":"byte[96]"},{"name":"B","type":"byte[96]"},{"name":"C","type":"byte[96]"},{"name":"Z","type":"byte[96]"},{"name":"T1","type":"byte[96]"},{"name":"T2","type":"byte[96]"},{"name":"T3","type":"byte[96]"},{"name":"Wxi","type":"byte[96]"},{"name":"Wxiw","type":"byte[96]"},{"name":"eval_a","type":"uint256"},{"name":"eval_b","type":"uint256"},{"name":"eval_c","type":"uint256"},{"name":"eval_s1","type":"uint256"},{"name":"eval_s2","type":"uint256"},{"name":"eval_zw","type":"uint256"}]},"methods":[{"name":"signalsAndProof","args":[{"type":"uint256[]","name":"signals"},{"type":"(byte[96],byte[96],byte[96],byte[96],byte[96],byte[96],byte[96],byte[96],byte[96],uint256,uint256,uint256,uint256,uint256,uint256)","struct":"PlonkProof","name":"proof"}],"returns":{"type":"void"},"actions":{"create":[],"call":["NoOp"]},"readonly":false,"events":[],"recommendations":{}}],"arcs":[22,28],"networks":{},"state":{"schema":{"global":{"ints":0,"bytes":0},"local":{"ints":0,"bytes":0}},"keys":{"global":{},"local":{},"box":{}},"maps":{"global":{},"local":{},"box":{}}},"bareActions":{"create":["NoOp"],"call":[]},"sourceInfo":{"approval":{"sourceInfo":[{"pc":[44],"errorMessage":"invalid array length header"},{"pc":[54],"errorMessage":"invalid number of bytes for arc4.dynamic_array<arc4.uint256>"},{"pc":[63],"errorMessage":"invalid number of bytes for contracts/plonk_bls12381.algo.ts::PlonkProof"}],"pcOffsetMethod":"none"},"clear":{"sourceInfo":[],"pcOffsetMethod":"none"}},"source":{"approval":"I3ByYWdtYSB2ZXJzaW9uIDExCiNwcmFnbWEgdHlwZXRyYWNrIGZhbHNlCgovLyBAYWxnb3JhbmRmb3VuZGF0aW9uL2FsZ29yYW5kLXR5cGVzY3JpcHQvYXJjNC9pbmRleC5kLnRzOjpDb250cmFjdC5hcHByb3ZhbFByb2dyYW0oKSAtPiB1aW50NjQ6Cm1haW46CiAgICAvLyBjb250cmFjdHMvcGxvbmtfdmVyaWZpZXIuYWxnby50czo2NgogICAgLy8gZXhwb3J0IGNsYXNzIFBsb25rU2lnbmFsc0FuZFByb29mIGV4dGVuZHMgQ29udHJhY3QgewogICAgdHhuIE51bUFwcEFyZ3MKICAgIGJ6IG1haW5fX19hbGdvdHNfXy5kZWZhdWx0Q3JlYXRlQDUKICAgIHB1c2hieXRlcyAweDQ0YTQ3ODhiIC8vIG1ldGhvZCAic2lnbmFsc0FuZFByb29mKHVpbnQyNTZbXSwoYnl0ZVs5Nl0sYnl0ZVs5Nl0sYnl0ZVs5Nl0sYnl0ZVs5Nl0sYnl0ZVs5Nl0sYnl0ZVs5Nl0sYnl0ZVs5Nl0sYnl0ZVs5Nl0sYnl0ZVs5Nl0sdWludDI1Nix1aW50MjU2LHVpbnQyNTYsdWludDI1Nix1aW50MjU2LHVpbnQyNTYpKXZvaWQiCiAgICB0eG5hIEFwcGxpY2F0aW9uQXJncyAwCiAgICBtYXRjaCBtYWluX3NpZ25hbHNBbmRQcm9vZl9yb3V0ZUAzCiAgICBlcnIKCm1haW5fc2lnbmFsc0FuZFByb29mX3JvdXRlQDM6CiAgICAvLyBjb250cmFjdHMvcGxvbmtfdmVyaWZpZXIuYWxnby50czo2NwogICAgLy8gcHVibGljIHNpZ25hbHNBbmRQcm9vZihzaWduYWxzOiBVaW50MjU2W10sIHByb29mOiBQbG9ua1Byb29mKTogdm9pZCB7fQogICAgdHhuIE9uQ29tcGxldGlvbgogICAgIQogICAgdHhuIEFwcGxpY2F0aW9uSUQKICAgICYmCiAgICBhc3NlcnQKICAgIGIgc2lnbmFsc0FuZFByb29mCgptYWluX19fYWxnb3RzX18uZGVmYXVsdENyZWF0ZUA1OgogICAgLy8gY29udHJhY3RzL3Bsb25rX3ZlcmlmaWVyLmFsZ28udHM6NjYKICAgIC8vIGV4cG9ydCBjbGFzcyBQbG9ua1NpZ25hbHNBbmRQcm9vZiBleHRlbmRzIENvbnRyYWN0IHsKICAgIHR4biBPbkNvbXBsZXRpb24KICAgICEKICAgIHR4biBBcHBsaWNhdGlvbklECiAgICAhCiAgICAmJgogICAgcmV0dXJuCgoKLy8gY29udHJhY3RzL3Bsb25rX3ZlcmlmaWVyLmFsZ28udHM6OlBsb25rU2lnbmFsc0FuZFByb29mLnNpZ25hbHNBbmRQcm9vZltyb3V0aW5nXSgpIC0+IHZvaWQ6CnNpZ25hbHNBbmRQcm9vZjoKICAgIC8vIGNvbnRyYWN0cy9wbG9ua192ZXJpZmllci5hbGdvLnRzOjY3CiAgICAvLyBwdWJsaWMgc2lnbmFsc0FuZFByb29mKHNpZ25hbHM6IFVpbnQyNTZbXSwgcHJvb2Y6IFBsb25rUHJvb2YpOiB2b2lkIHt9CiAgICB0eG5hIEFwcGxpY2F0aW9uQXJncyAxCiAgICBkdXAKICAgIHB1c2hpbnQgMAogICAgZXh0cmFjdF91aW50MTYgLy8gb24gZXJyb3I6IGludmFsaWQgYXJyYXkgbGVuZ3RoIGhlYWRlcgogICAgcHVzaGludCAzMgogICAgKgogICAgcHVzaGludCAyCiAgICArCiAgICBzd2FwCiAgICBsZW4KICAgID09CiAgICBhc3NlcnQgLy8gaW52YWxpZCBudW1iZXIgb2YgYnl0ZXMgZm9yIGFyYzQuZHluYW1pY19hcnJheTxhcmM0LnVpbnQyNTY+CiAgICB0eG5hIEFwcGxpY2F0aW9uQXJncyAyCiAgICBsZW4KICAgIHB1c2hpbnQgMTA1NgogICAgPT0KICAgIGFzc2VydCAvLyBpbnZhbGlkIG51bWJlciBvZiBieXRlcyBmb3IgY29udHJhY3RzL3Bsb25rX2JsczEyMzgxLmFsZ28udHM6OlBsb25rUHJvb2YKICAgIHB1c2hpbnQgMQogICAgcmV0dXJuCg==","clear":"I3ByYWdtYSB2ZXJzaW9uIDExCiNwcmFnbWEgdHlwZXRyYWNrIGZhbHNlCgovLyBAYWxnb3JhbmRmb3VuZGF0aW9uL2FsZ29yYW5kLXR5cGVzY3JpcHQvYmFzZS1jb250cmFjdC5kLnRzOjpCYXNlQ29udHJhY3QuY2xlYXJTdGF0ZVByb2dyYW0oKSAtPiB1aW50NjQ6Cm1haW46CiAgICBwdXNoaW50IDEKICAgIHJldHVybgo="},"byteCode":{"approval":"CzEbQQAYgAREpHiLNhoAjgEAAQAxGRQxGBBEQgAIMRkUMRgUEEM2GgFJgQBZgSALgQIITBUSRDYaAhWBoAgSRIEBQw==","clear":"C4EBQw=="},"compilerInfo":{"compiler":"puya","compilerVersion":{"major":5,"minor":8,"patch":0}},"events":[],"templateVariables":{}}';

/** The ARC56 contract this client was generated from */
export const APP_SPEC = JSON.parse(ARC56_JSON) as ARC56Contract;

// Aliases for non-encoded ABI values
type uint256 = bigint;

// Type definitions for ARC56 structs
export type PlonkProof = {
  A: Uint8Array;
  B: Uint8Array;
  C: Uint8Array;
  Z: Uint8Array;
  T1: Uint8Array;
  T2: Uint8Array;
  T3: Uint8Array;
  Wxi: Uint8Array;
  Wxiw: Uint8Array;
  eval_a: uint256;
  eval_b: uint256;
  eval_c: uint256;
  eval_s1: uint256;
  eval_s2: uint256;
  eval_zw: uint256;
};

export type PlonkSignalsAndProofReturnTypes = {
  signalsAndProof: void;
};

export class PlonkSignalsAndProofClient extends ARC56AppClient {
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
        proof: PlonkProof;
      }>,
    ): MethodParams<PlonkSignalsAndProofReturnTypes["signalsAndProof"]> => {
      return this.getParams<PlonkSignalsAndProofReturnTypes["signalsAndProof"]>(
        {
          method: "signalsAndProof",
          ...methodParams,
          methodArgs: [methodParams.args.signals, methodParams.args.proof],
        },
      );
    },
  };

  call = {
    signalsAndProof: async (
      methodParams: TypedMethodParams<{
        signals: uint256[];
        proof: PlonkProof;
      }>,
    ): Promise<{
      result: MethodExecutionResult;
      returnValue: PlonkSignalsAndProofReturnTypes["signalsAndProof"];
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
      appClient: PlonkSignalsAndProofClient;
      result: BareExecutionResult;
      appId: bigint;
      appAddress: algosdk.Address;
    }> => {
      const { appId, appAddress, result } = await ARC56AppClient.bareCreate({
        arc56: APP_SPEC,
        ...params,
      });
      return {
        appClient: new PlonkSignalsAndProofClient({
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

export default PlonkSignalsAndProofClient;
