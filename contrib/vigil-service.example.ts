/**
 * Example: NestJS service that spawns sandwich-detect CLI and consumes JSON lines.
 * Copy and adapt for your Vigil backend.
 *
 * Usage:
 *   1. Build the CLI:  cargo build --release
 *   2. Place the binary where NestJS can find it
 *   3. Import this service into your NestJS module
 */

import { Injectable, OnModuleInit, OnModuleDestroy, Logger } from "@nestjs/common";
import { ChildProcess, spawn } from "child_process";
import { createInterface } from "readline";
import type { SandwichAttack } from "./vigil-types";

@Injectable()
export class SandwichDetectorService implements OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger(SandwichDetectorService.name);
  private process: ChildProcess | null = null;

  constructor(
    // inject your DB service, WebSocket gateway, alert service, etc.
    // private readonly prisma: PrismaService,
    // private readonly ws: SandwichGateway,
  ) {}

  onModuleInit() {
    this.start();
  }

  onModuleDestroy() {
    this.stop();
  }

  private start() {
    const rpcUrl = process.env.RPC_URL;
    if (!rpcUrl) {
      this.logger.error("RPC_URL not set");
      return;
    }

    this.process = spawn("sandwich-detect", [
      "--rpc", rpcUrl,
      "--follow",
      "--format", "json",
      "--poll-interval", "1000",
    ]);

    const rl = createInterface({ input: this.process.stdout! });

    rl.on("line", (line) => {
      try {
        const attack: SandwichAttack = JSON.parse(line);
        this.handleAttack(attack);
      } catch {
        // stderr log lines or malformed — skip
      }
    });

    this.process.stderr?.on("data", (data) => {
      // CLI info/warn logs go to stderr
      this.logger.debug(data.toString().trim());
    });

    this.process.on("exit", (code) => {
      this.logger.warn(`sandwich-detect exited with code ${code}, restarting...`);
      setTimeout(() => this.start(), 5000);
    });

    this.logger.log("sandwich-detect started");
  }

  private stop() {
    this.process?.kill();
    this.process = null;
  }

  private async handleAttack(attack: SandwichAttack) {
    this.logger.log(
      `Sandwich at slot ${attack.slot}: ${attack.attacker.slice(0, 8)}... ` +
      `on ${attack.dex}, profit=${attack.estimated_attacker_profit}`,
    );

    // ---- Vigil-specific logic goes here ----
    //
    // await this.prisma.sandwichAttack.create({ data: { ... } });
    // this.ws.broadcast("sandwich", attack);
    // await this.alertService.notify(attack);
  }
}
