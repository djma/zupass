import {
  PCDAddRequest,
  PCDProveAndAddRequest,
  PCDRequest,
  PCDRequestType
} from "@pcd/passport-interface";
import { useEffect } from "react";
import { useLocation } from "react-router-dom";
import { useDispatch, useSelf } from "../../../src/appHooks";
import { validateRequest } from "../../../src/passportRequest";
import { useSyncE2EEStorage } from "../../../src/useSyncE2EEStorage";
import { err } from "../../../src/util";
import { AppContainer } from "../../shared/AppContainer";
import { JustAddScreen } from "./JustAddScreen";
import { ProveAndAddScreen } from "./ProveAndAddScreen";

/**
 * Asks user if they want to add the given PCD to their passport. The
 * PCD can either be a `SerializedPCD` passed in via a url, or one that
 * is freshly generated in-passport via a proving screen.
 */
export function AddScreen() {
  useSyncE2EEStorage();
  const dispatch = useDispatch();
  const self = useSelf();
  const location = useLocation();
  const params = new URLSearchParams(location.search);
  const request = validateRequest(params);

  const screen = getScreen(request);
  useEffect(() => {
    if (screen === null) {
      err(dispatch, "Unsupported request", `Expected a PCD ADD request`);
    }
  }, [dispatch, screen]);

  if (self == null) {
    sessionStorage.pendingAddRequest = JSON.stringify(request);
    window.location.href = "/#/login";
    window.location.reload();
    return null;
  }

  if (screen == null) {
    // Need AppContainer to display error
    return <AppContainer bg="gray" />;
  }
  return screen;
}

function getScreen(request: PCDRequest) {
  switch (request.type) {
    case PCDRequestType.ProveAndAdd:
      return <ProveAndAddScreen request={request as PCDProveAndAddRequest} />;
    case PCDRequestType.Add:
      return <JustAddScreen request={request as PCDAddRequest} />;
    default:
      return null;
  }
}
