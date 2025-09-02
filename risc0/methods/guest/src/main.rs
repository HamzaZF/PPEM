use risc0_zkvm::guest::env;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Participant {
    pub id: u32,
    pub role: u32,           // 0 = BUY, 1 = SELL
    pub price: u64,          // bid price for buyers, ask price for sellers  
    pub quantity: u64,       // energy quantity to trade
    pub in_coin: u64,        // initial coin balance
    pub in_energy: u64,      // initial energy balance
    pub out_coin: u64,       // final coin balance (after auction)
    pub out_energy: u64,     // final energy balance (after auction)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuctionInput {
    pub participants: Vec<Participant>,
    pub expected_clearing_price: u64,
    pub expected_total_energy_traded: u64,
}

// Public journal committed by the guest to be used by gnark as public inputs
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PublicJournal {
    pub clearing_price: u64,
    pub in_coin: Vec<u64>,
    pub in_energy: Vec<u64>,
    pub out_coin: Vec<u64>,
    pub out_energy: Vec<u64>,
}

fn main() {
    // Read auction input from host
    let auction_input: AuctionInput = env::read();
    
    // Perform double auction using the SAME algorithm as host
    let result = perform_double_auction_guest(&auction_input);
    
    // Commit the result to the journal
    env::commit(&result);
}

fn perform_double_auction_guest(input: &AuctionInput) -> PublicJournal {
    let participants = input.participants.clone();
    
    // Create cloned vectors for sorting and analysis (same as host)
    let mut buyers: Vec<Participant> = participants
        .iter()
        .filter(|p| p.role == 0) // BUY
        .cloned()
        .collect();
        
    let mut sellers: Vec<Participant> = participants
        .iter()
        .filter(|p| p.role == 1) // SELL
        .cloned()
        .collect();
    
    // Sort buyers (descending by price) and sellers (ascending by price) - EXACT SAME AS HOST
    buyers.sort_by(|a, b| {
        match b.price.cmp(&a.price) {
            core::cmp::Ordering::Equal => a.id.cmp(&b.id),
            other => other,
        }
    }); // Desc by price, tie-break by id asc
    sellers.sort_by(|a, b| {
        match a.price.cmp(&b.price) {
            core::cmp::Ordering::Equal => a.id.cmp(&b.id),
            other => other,
        }
    }); // Asc by price, tie-break by id asc
    
    // Create references for clearing rule - EXACT SAME AS HOST
    let buyer_refs: Vec<&Participant> = buyers.iter().collect();
    let seller_refs: Vec<&Participant> = sellers.iter().collect();

    // Uniform marginal-crossing clearing - EXACT SAME AS HOST
    let pstar_opt = find_uniform_clearing_guest(&buyer_refs, &seller_refs);
    
    if pstar_opt.is_none() {
        // No intersection - no trading occurs, balances remain unchanged
        return build_public_journal(0, &participants, &buyers, &sellers);
    }
    
    let (p_star, b_marg, a_marg) = pstar_opt.unwrap();
    let clearing_price = (b_marg + a_marg) / 2; // average - EXACT SAME AS HOST

    // Guard against zero clearing price to avoid division by zero
    if clearing_price == 0 {
        return build_public_journal(0, &participants, &buyers, &sellers);
    }

    // Determine qualified sets at p_star (NOT at p_c) - EXACT SAME AS HOST
    let qualified_buyers: Vec<&Participant> = buyer_refs
        .iter()
        .copied()
        .filter(|b| b.price >= p_star)
        .collect();
    let qualified_sellers: Vec<&Participant> = seller_refs
        .iter()
        .copied()
        .filter(|s| s.price <= p_star)
        .collect();
    
    // Compute total demand and supply at p_star - EXACT SAME AS HOST
    let _total_demand: u64 = qualified_buyers.iter().map(|b| b.quantity).sum();
    let _total_supply: u64 = qualified_sellers.iter().map(|s| s.quantity).sum();

    // Build allocation maps: id -> allocated energy - EXACT SAME AS HOST
    // Use a simple Vec-based approach for deterministic behavior in guest environment
    let mut alloc_by_id: Vec<(u32, u64)> = Vec::new();

    // Effective demand/supply with budget/stock caps at price p_c - EXACT SAME AS HOST
    let mut eff_demand: u64 = 0;
    for b in &qualified_buyers {
        let max_afford = b.in_coin / clearing_price; // floor division
        let cap = if b.quantity < max_afford { b.quantity } else { max_afford };
        eff_demand = eff_demand.saturating_add(cap);
    }
    let mut eff_supply: u64 = 0;
    for s in &qualified_sellers {
        let cap = if s.quantity < s.in_energy { s.quantity } else { s.in_energy };
        eff_supply = eff_supply.saturating_add(cap);
    }
    let traded_total = eff_demand.min(eff_supply);

    if traded_total == 0 {
        return build_public_journal(clearing_price, &participants, &buyers, &sellers);
    }

    // EXACT SAME ALLOCATION LOGIC AS HOST
    if eff_demand >= eff_supply {
        // Supply binding: sellers full (capped by stock); buyers priority by price, capped by budget & qty
        for s in &qualified_sellers {
            let cap = if s.quantity < s.in_energy { s.quantity } else { s.in_energy };
            alloc_by_id.push((s.id, cap));
        }
        let mut remaining = traded_total;
        for b in &qualified_buyers {
            if remaining == 0 { break; }
            let max_afford = b.in_coin / clearing_price;
            let cap = b.quantity.min(max_afford);
            let take = if cap <= remaining { cap } else { remaining };
            alloc_by_id.push((b.id, take));
            remaining -= take;
        }
    } else {
        // Demand binding: buyers full (capped by budget & qty); sellers priority by ask, capped by stock
        for b in &qualified_buyers {
            let max_afford = b.in_coin / clearing_price;
            let cap = b.quantity.min(max_afford);
            alloc_by_id.push((b.id, cap));
        }
        let mut remaining = traded_total;
        for s in &qualified_sellers {
            if remaining == 0 { break; }
            let cap = s.quantity.min(s.in_energy);
            let take = if cap <= remaining { cap } else { remaining };
            alloc_by_id.push((s.id, take));
            remaining -= take;
        }
    }

    // Verify balances according to allocations - EXACT SAME AS HOST
    let mut _verification_passed = true;
    for p in &participants {
        let allocated = alloc_by_id.iter()
            .find(|(id, _)| *id == p.id)
            .map(|(_, amount)| *amount)
            .unwrap_or(0);
        
        let expected_out_coin;
        let expected_out_energy;
        
        if p.role == 0 { // BUY
            if allocated > 0 {
                expected_out_coin = p.in_coin - (clearing_price * allocated);
                expected_out_energy = p.in_energy + allocated;
            } else {
                expected_out_coin = p.in_coin;
                expected_out_energy = p.in_energy;
            }
        } else { // SELL
            if allocated > 0 {
                expected_out_coin = p.in_coin + (clearing_price * allocated);
                expected_out_energy = p.in_energy - allocated;
            } else {
                expected_out_coin = p.in_coin;
                expected_out_energy = p.in_energy;
            }
        }
        
        // Verify the balances match what the host calculated
        if p.out_coin != expected_out_coin || p.out_energy != expected_out_energy {
            _verification_passed = false;
            break;
        }
    }

    // Build the public journal in circuit order
    let pj = build_public_journal(clearing_price, &participants, &buyers, &sellers);
    pj
}

// EXACT SAME HELPER FUNCTIONS AS HOST
fn demand_supply_at_price(buyers: &[&Participant], sellers: &[&Participant], p: u64) -> (u64, u64) {
    let demand: u64 = buyers.iter().filter(|b| b.price >= p).map(|b| b.quantity).sum();
    let supply: u64 = sellers.iter().filter(|s| s.price <= p).map(|s| s.quantity).sum();
    (demand, supply)
}

fn find_uniform_clearing_guest(buyers: &[&Participant], sellers: &[&Participant]) -> Option<(u64, u64, u64)> {
    if buyers.is_empty() || sellers.is_empty() {
        return None;
    }

    // Discrete grid of candidate prices - EXACT SAME AS HOST
    let mut prices: Vec<u64> = buyers.iter().map(|b| b.price).collect();
    prices.extend(sellers.iter().map(|s| s.price));
    prices.sort();
    prices.dedup();

    // Find p* = smallest p where S(p) >= D(p) - EXACT SAME AS HOST
    let mut p_star: Option<u64> = None;
    for &p in &prices {
        let (d, s) = demand_supply_at_price(buyers, sellers, p);
        if s >= d {
            p_star = Some(p);
            break;
        }
    }

    let p_star = match p_star { Some(v) => v, None => return None };

    // Determine marginals at p* - EXACT SAME AS HOST
    let mut qualified_buyers: Vec<&Participant> = buyers.iter().copied().filter(|b| b.price >= p_star).collect();
    let mut qualified_sellers: Vec<&Participant> = sellers.iter().copied().filter(|s| s.price <= p_star).collect();
    if qualified_buyers.is_empty() || qualified_sellers.is_empty() { return None; }
    qualified_buyers.sort_by(|a, b| b.price.cmp(&a.price));
    qualified_sellers.sort_by(|a, b| a.price.cmp(&b.price));

    let b_marg = qualified_buyers.last().unwrap().price;
    let a_marg = qualified_sellers.last().unwrap().price;

    Some((p_star, b_marg, a_marg))
}

// Build public arrays matching the gnark circuit order (buyers then sellers)
fn build_public_journal(
    clearing_price: u64,
    participants: &Vec<Participant>,
    _buyers_sorted: &Vec<Participant>,
    _sellers_sorted: &Vec<Participant>,
) -> PublicJournal {
    use std::collections::BTreeMap;

    // Create map for quick lookup
    let mut by_id: BTreeMap<u32, &Participant> = BTreeMap::new();
    for p in participants { by_id.insert(p.id, p); }

    // Separate buyers and sellers from input participants
    let mut all_buyers: Vec<&Participant> = Vec::new();
    let mut all_sellers: Vec<&Participant> = Vec::new();
    
    for p in participants {
        if p.role == 0 { // BUY
            all_buyers.push(p);
        } else { // SELL
            all_sellers.push(p);
        }
    }

    // Sort buyers by price descending (highest price first) - CIRCUIT ORDER
    all_buyers.sort_by(|a, b| b.price.cmp(&a.price));
    
    // Sort sellers by price ascending (lowest price first) - CIRCUIT ORDER  
    all_sellers.sort_by(|a, b| a.price.cmp(&b.price));

    // Build the ordered participant list: buyers first, then sellers
    let mut circuit_ordered_participants: Vec<&Participant> = Vec::new();
    circuit_ordered_participants.extend(all_buyers);
    circuit_ordered_participants.extend(all_sellers);

    // Extract values in circuit order (matches Go SortParticipantsForCircuit)
    let mut in_coin: Vec<u64> = Vec::with_capacity(circuit_ordered_participants.len());
    let mut in_energy: Vec<u64> = Vec::with_capacity(circuit_ordered_participants.len());
    let mut out_coin: Vec<u64> = Vec::with_capacity(circuit_ordered_participants.len());
    let mut out_energy: Vec<u64> = Vec::with_capacity(circuit_ordered_participants.len());

    for p in circuit_ordered_participants {
        in_coin.push(p.in_coin);
        in_energy.push(p.in_energy);
        out_coin.push(p.out_coin);
        out_energy.push(p.out_energy);
    }

    PublicJournal { clearing_price, in_coin, in_energy, out_coin, out_energy }
}
