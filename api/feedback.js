const nodemailer = require("nodemailer");

const RECIPIENT = "recap@entrenous972.fr";
const ALLOWED_TYPES = new Set(["satisfaction","suggestion","bug","feedback"]);

module.exports = async function handler(req, res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
  if (req.method === "OPTIONS") return res.status(204).end();
  if (req.method !== "POST") return res.status(405).json({ error: "Méthode non autorisée." });

  try {
    const { SUPABASE_URL, SUPABASE_PUBLISHABLE_KEY, SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS } = process.env;
    if (![SUPABASE_URL, SUPABASE_PUBLISHABLE_KEY, SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS].every(Boolean)) {
      return res.status(503).json({ error: "Le service e-mail n'est pas encore configuré." });
    }

    const auth = req.headers.authorization || "";
    if (!auth.startsWith("Bearer ")) return res.status(401).json({ error: "Connexion requise." });
    const authResponse = await fetch(`${SUPABASE_URL}/auth/v1/user`, {
      headers: { apikey: SUPABASE_PUBLISHABLE_KEY, Authorization: auth }
    });
    if (!authResponse.ok) return res.status(401).json({ error: "Session invalide. Reconnecte-toi." });
    const user = await authResponse.json();

    const { type, note, version } = req.body || {};
    const cleanNote = typeof note === "string" ? note.trim() : "";
    if (!cleanNote || cleanNote.length > 5000) return res.status(400).json({ error: "Le retour doit contenir entre 1 et 5 000 caractères." });

    const transporter = nodemailer.createTransport({
      host: SMTP_HOST,
      port: Number(SMTP_PORT),
      secure: Number(SMTP_PORT) === 465,
      auth: { user: SMTP_USER, pass: SMTP_PASS }
    });
    await transporter.sendMail({
      from: { name: "Entre Nous972", address: SMTP_USER },
      to: RECIPIENT,
      replyTo: user.email || undefined,
      subject: `ENTRE NOUS — ${ALLOWED_TYPES.has(type) ? type : "retour utilisateur"}`,
      text: [
        "Nouveau retour transmis depuis ENTRE NOUS",
        "",
        `Catégorie : ${ALLOWED_TYPES.has(type) ? type : "non précisée"}`,
        `Date : ${new Date().toISOString()}`,
        `Version : ${String(version || "non précisée").slice(0, 100)}`,
        `Utilisateur : ${user.email || "compte anonyme"}`,
        `Identifiant : ${user.id}`,
        "",
        cleanNote
      ].join("\n")
    });
    return res.status(200).json({ ok: true });
  } catch (error) {
    console.error("Feedback email failed:", error);
    return res.status(500).json({ error: "L'envoi du retour a échoué. Réessaie plus tard." });
  }
};
