export const WIT_WORLD = "chio:guard@0.2.0" as const;

export interface GuardRequest {
  toolName: string;
  serverId: string;
  agentId: string;
  arguments: string;
  scopes: string[];
  actionType?: string;
  extractedPath?: string;
  extractedTarget?: string;
  filesystemRoots: string[];
  matchedGrantIndex?: number;
}

export interface VerdictAllow {
  tag: "allow";
}

export interface VerdictDeny {
  tag: "deny";
  val: string;
}

export type Verdict = VerdictAllow | VerdictDeny;

export interface Host {
  log(level: number, msg: string): void;
  getConfig(key: string): string | undefined;
  getTimeUnixSecs(): bigint;
  fetchBlob(handle: number, offset: bigint, len: number): Uint8Array;
}

function unavailable(name: string): never {
  throw new Error(`${name} is only available inside a chio:guard@0.2.0 component`);
}

export const host: Host = {
  log(_level: number, _msg: string): void {
    unavailable("host.log");
  },
  getConfig(_key: string): string | undefined {
    unavailable("host.getConfig");
  },
  getTimeUnixSecs(): bigint {
    unavailable("host.getTimeUnixSecs");
  },
  fetchBlob(_handle: number, _offset: bigint, _len: number): Uint8Array {
    unavailable("host.fetchBlob");
  },
};

export class PolicyContext {
  readonly id: string;
  readonly handle: number;

  constructor(id: string, handle = 0) {
    this.id = id;
    this.handle = handle;
  }

  read(offset: bigint, len: number): Uint8Array {
    return host.fetchBlob(this.handle, offset, len);
  }

  close(): void {
    return;
  }
}

export function allow(): VerdictAllow {
  return { tag: "allow" };
}

export function deny(reason: string): VerdictDeny {
  return { tag: "deny", val: reason };
}
