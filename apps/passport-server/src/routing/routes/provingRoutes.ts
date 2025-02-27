import {
  PendingPCD,
  ProveRequest,
  StatusRequest,
  StatusResponse,
} from "@pcd/passport-interface";
import express, { Request, Response } from "express";
import { ApplicationContext, GlobalServices } from "../../types";
import { logger } from "../../util/logger";

export function initProvingRoutes(
  app: express.Application,
  _context: ApplicationContext,
  { provingService, rollbarService }: GlobalServices
): void {
  logger("[INIT] initializing proving routes");

  app.post("/pcds/prove", async (req: Request, res: Response) => {
    logger("/pcds/prove received:", req.body);
    const request = req.body as ProveRequest;
    try {
      const pending: PendingPCD = await provingService.enqueueProofRequest(
        request
      );
      res.json(pending);
    } catch (e) {
      logger("/pcds/prove error: ", e);
      rollbarService?.reportError(e);
      res.sendStatus(500);
    }
  });

  app.get("/pcds/supported", async (req: Request, res: Response) => {
    try {
      res.json(provingService.getSupportedPCDTypes());
    } catch (e) {
      logger("/pcds/supported error: ", e);
      rollbarService?.reportError(e);
      res.sendStatus(500);
    }
  });

  app.post("/pcds/status", async (req: Request, res: Response) => {
    const statusRequest = req.body as StatusRequest;
    try {
      const statusResponse: StatusResponse = provingService.getPendingPCDStatus(
        statusRequest.hash
      );
      res.json(statusResponse);
    } catch (e) {
      logger("/pcds/status error:", e);
      rollbarService?.reportError(e);
      res.sendStatus(500);
    }
  });
}
