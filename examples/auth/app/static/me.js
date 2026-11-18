// The live connection is cut by the server once the session ends, with close code 1008; the page says
// so rather than reconnecting, since a reconnect would only be refused.
const live = document.getElementById("live");
const ws = new WebSocket((location.protocol === "https:" ? "wss://" : "ws://") + location.host + "/live");
ws.onopen = () => { live.textContent = "open"; };
ws.onclose = (ev) => {
  live.textContent = ev.code === 1008 ? "session ended" : "closed (" + ev.code + ")";
};
