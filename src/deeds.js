// Fictional deeds only: every person, company and address below is made up.
import { randomBytes } from 'node:crypto';

export const SEED = [
  {
    ref: 'NTR-0001', kind: 'Deed of sale', title: 'Sale of 14 Rue des Glycines, Nantes',
    body: 'Between Camille Ferrand (seller) and the Orbital Bakery cooperative (buyer). A two-storey townhouse with a walled garden and a bread oven that still works. Price: 412,000 €, paid at signing. Keys handed over on 2 December 2026. The seller keeps the lemon tree.',
  },
  {
    ref: 'NTR-0002', kind: 'Last will', title: 'Last will of Ada Brightwater',
    body: 'I leave my collection of 312 vintage maps to the municipal library of Quimper, my sailboat "Marée Basse" to my niece Lou, and my recipe for salted caramel to whoever finds it in the blue tin. Executor: Maître Jules Ombre.',
  },
  {
    ref: 'NTR-0003', kind: 'Non-disclosure agreement', title: 'NDA, Nimbus Logistics and Pelican Robotics',
    body: 'Nimbus Logistics will show Pelican Robotics the routing tables of its night depot in Rungis. Pelican keeps them confidential for five years and uses them only to size a fleet of 40 sorting robots. Penalty for disclosure: 250,000 €.',
  },
  {
    ref: 'NTR-0004', kind: 'Lease', title: 'Lease of Studio 3B, 7 Quai Vauban, Lille',
    body: 'Landlord: SCI Les Trois Ponts. Tenant: Inès Marchal. Furnished studio, 31 m², third floor, view on the canal. Rent 690 € a month, charges included. Deposit 1,380 €. Pets allowed: one cat, named in the annex as "Monsieur Pixel".',
  },
  {
    ref: 'NTR-0005', kind: 'Power of attorney', title: 'Power of attorney, Hugo Lenormand',
    body: 'Hugo Lenormand, on a research vessel in the Southern Ocean until March 2027, gives his sister Jeanne Lenormand power to sign, in his name, the sale of his share of the family vineyard in Saumur, at no less than 180,000 €.',
  },
];

const PARTIES = ['Basile Corentin', 'Maëlle Quintard', 'the Hôtel des Brumes', 'Théo Arnaud', 'Lina Vasseur', 'the Atelier Cobalt', 'Nora Desrosiers', 'Gaspard Peyrol'];
const KINDS = [
  ['Deed of sale', (a, b) => `Sale of a fisherman's cottage in Douarnenez`, (a, b) => `Between ${a} (seller) and ${b} (buyer). Price: ${120 + rnd(300)},000 €. The blue shutters stay.`],
  ['Lease', () => `Lease of a workshop in Roubaix`, (a, b) => `Landlord: ${a}. Tenant: ${b}. 85 m² under a glass roof, ${900 + rnd(600)} € a month.`],
  ['Non-disclosure agreement', (a, b) => `NDA, ${cap(a)} and ${cap(b)}`, (a, b) => `${cap(a)} will share its supplier list with ${b}, to be kept confidential for ${2 + rnd(5)} years.`],
  ['Last will', (a) => `Last will of ${cap(a)}`, (a, b) => `I leave my bicycle collection to ${b} and my piano to the conservatory of Angers.`],
];

function rnd(n) { return randomBytes(2).readUInt16BE(0) % n; }
function cap(s) { return s.charAt(0).toUpperCase() + s.slice(1); }

// A fresh fictional deed for the "seal a deed" form.
export function draftDeed() {
  const a = PARTIES[rnd(PARTIES.length)];
  let b = PARTIES[rnd(PARTIES.length)];
  if (b === a) b = PARTIES[(PARTIES.indexOf(a) + 1) % PARTIES.length];
  const [kind, title, body] = KINDS[rnd(KINDS.length)];
  return { kind, title: title(a, b), body: body(a, b) };
}

const ALPHABET = '23456789ABCDEFGHJKLMNPQRSTUVWXYZ';
export function newRef() {
  const bytes = randomBytes(6);
  return `NTR-${Array.from(bytes, (x) => ALPHABET[x % ALPHABET.length]).join('')}`;
}

export const LIMITS = { title: 120, body: 1200, kind: 40 };

export function checkDeed(input) {
  const title = String(input?.title ?? '').trim();
  const body = String(input?.body ?? '').trim();
  const kind = String(input?.kind ?? 'Deed').trim() || 'Deed';
  if (!title || !body) return { ok: false, error: 'A deed needs a title and a text' };
  if (title.length > LIMITS.title || body.length > LIMITS.body || kind.length > LIMITS.kind) {
    return { ok: false, error: `Too long: ${LIMITS.title} characters for the title, ${LIMITS.body} for the text` };
  }
  return { ok: true, deed: { title, body, kind } };
}
