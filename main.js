
document.addEventListener("DOMContentLoaded", () => {
  // Socket.IO connection
  let socket;
  if (typeof io !== "undefined") {
    socket = io();
    // Join personal room if session provided by server-sent script
    socket.on("connect", () => {
      console.log("Socket connected");
    });
    socket.on("new_support", data => {
      makeToast("Yeni destek: " + data.kullanici + " - " + data.konu);
      // optionally reload admin support list
    });
    socket.on("support_reply", data => {
      makeToast("Admin yanıtı: " + data.yanit);
      updateChat(data.ticket_id, data.sender, data.yanit, data.tarih);
    });
    socket.on("chat_message", data => {
      // chat messages update
      updateChat(data.ticket_id, data.sender, data.text, data.tarih);
    });
  }

  // Toast
  function makeToast(msg, duration=5000){
    const container = document.querySelector(".toast-container");
    if (!container) return;
    const t = document.createElement("div");
    t.className="toast";
    t.innerHTML= "<div>"+msg+"</div><div class='close'>✕</div>";
    container.appendChild(t);
    const remover= () => { t.classList.add("hide"); setTimeout(()=>t.remove(),300); };
    t.querySelector(".close")?.addEventListener("click", remover);
    setTimeout(remover, duration);
  }

  window.makeToast = makeToast;

  // Update chat window if exists
  function updateChat(ticket_id, sender, text, tarih){
    const container = document.querySelector(`#chat-messages-${ticket_id}`);
    if (!container) return;
    const msg = document.createElement("div");
    msg.className="ticket";
    msg.innerHTML = `<div><strong>${sender}:</strong> ${text}</div><div><small>${tarih}</small></div>`;
    container.appendChild(msg);
    container.scrollTop = container.scrollHeight;
  }

  // Send chat message forms
  document.querySelectorAll(".chat-form").forEach(form => {
    form.addEventListener("submit", e => {
      e.preventDefault();
      const ticket_id = form.dataset.ticket;
      const input = form.querySelector("input[name=message]");
      const text = input.value.trim();
      if (!text) return;
      if (socket) {
        socket.emit("chat_message", { ticket_id, text });
        input.value="";
      }
    });
  });

  // Show initial replies
  if (window.NEW_REPLIES && Array.isArray(window.NEW_REPLIES)){
    window.NEW_REPLIES.forEach(r => {
      makeToast("Yeni destek cevabı: " + r.konu + " → " + r.yanit);
    });
  }
});
