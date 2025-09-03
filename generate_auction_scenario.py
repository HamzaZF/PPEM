#!/usr/bin/env python3
"""
Auction Scenario Generator for PPEM
Generates realistic auction scenarios with guaranteed market intersection (for testing purposes)
"""

import json
import random
import argparse
from typing import List, Dict, Tuple
import sys

class AuctionScenarioGenerator:
    def __init__(self, num_participants: int):
        self.num_participants = num_participants
        self.buyer_ratio = 0.5  # Fixed at 50% buyers
        self.num_buyers = int(num_participants * self.buyer_ratio)
        self.num_sellers = num_participants - self.num_buyers
        
        # Ensure at least one of each type
        if self.num_buyers == 0 and num_participants > 1:
            self.num_buyers = 1
            self.num_sellers = num_participants - 1
        elif self.num_sellers == 0 and num_participants > 1:
            self.num_sellers = 1
            self.num_buyers = num_participants - 1
    
    def generate_scenario(self, scenario_name: str = "Generated_PPEM_Auction") -> Dict:
        """Generate a complete auction scenario with guaranteed intersection"""
        
        # Step 1: Determine clearing price (realistic range)
        clearing_price = random.randint(45, 65)
        
        # Step 2: Generate participant data
        participants = []
        qualified_buyers = []
        qualified_sellers = []
        
        # Generate buyers
        for i in range(self.num_buyers):
            participant_id = len(participants)
            
            # Determine if this buyer should be qualified (60% chance)
            is_qualified = random.random() < 0.6 or len(qualified_buyers) < max(1, self.num_buyers // 2)
            
            if is_qualified:
                # Qualified buyers bid above clearing price
                price = clearing_price + random.randint(1, 20)
                quantity = random.randint(8, 25)
                qualified_buyers.append((participant_id, quantity))
            else:
                # Unqualified buyers bid below clearing price
                price = clearing_price - random.randint(1, 15)
                quantity = random.randint(5, 20)
            
            # Generate realistic balances
            in_coin = price * quantity * 2 + random.randint(500, 1500)
            in_energy = random.randint(80, 180)
            
            participants.append({
                "id": participant_id,
                "role": 0,  # BUY
                "price": price,
                "quantity": quantity,
                "in_coin": in_coin,
                "in_energy": in_energy,
                "out_coin": in_coin,  # Will be updated after auction
                "out_energy": in_energy  # Will be updated after auction
            })
        
        # Generate sellers
        for i in range(self.num_sellers):
            participant_id = len(participants)
            
            # Determine if this seller should be qualified (60% chance)
            is_qualified = random.random() < 0.6 or len(qualified_sellers) < max(1, self.num_sellers // 2)
            
            if is_qualified:
                # Qualified sellers ask below clearing price
                price = clearing_price - random.randint(1, 20)
                quantity = random.randint(8, 25)
                qualified_sellers.append((participant_id, quantity))
            else:
                # Unqualified sellers ask above clearing price
                price = clearing_price + random.randint(1, 15)
                quantity = random.randint(5, 20)
            
            # Generate realistic balances
            in_coin = random.randint(1000, 3000)
            in_energy = quantity * 2 + random.randint(50, 150)
            
            participants.append({
                "id": participant_id,
                "role": 1,  # SELL
                "price": price,
                "quantity": quantity,
                "in_coin": in_coin,
                "in_energy": in_energy,
                "out_coin": in_coin,  # Will be updated after auction
                "out_energy": in_energy  # Will be updated after auction
            })
        
        # Step 3: Ensure supply = demand by adjusting qualified participants
        total_demand = sum(qty for _, qty in qualified_buyers)
        total_supply = sum(qty for _, qty in qualified_sellers)
        
        # Adjust to create perfect intersection
        if total_demand > total_supply:
            # Reduce buyer quantities
            excess = total_demand - total_supply
            self._adjust_quantities(participants, qualified_buyers, -excess)
        elif total_supply > total_demand:
            # Reduce seller quantities
            excess = total_supply - total_demand
            self._adjust_quantities(participants, qualified_sellers, -excess)
        
        # Recalculate totals
        total_traded = sum(participants[pid]["quantity"] for pid, _ in qualified_buyers)
        
        # Step 4: Calculate final balances
        self._calculate_final_balances(participants, qualified_buyers, qualified_sellers, clearing_price)
        
        # Step 5: Create scenario structure
        scenario = {
            "scenario_name": scenario_name,
            "description": f"Generated PPEM auction with {self.num_participants} participants ({self.num_buyers} buyers, {self.num_sellers} sellers)",
            "expected_clearing_price": clearing_price,
            "expected_total_energy_traded": total_traded,
            "participants": participants
        }
        
        return scenario
    
    def _adjust_quantities(self, participants: List[Dict], qualified_list: List[Tuple], adjustment: int):
        """Adjust quantities to ensure supply = demand"""
        remaining_adjustment = abs(adjustment)
        
        for pid, _ in qualified_list:
            if remaining_adjustment <= 0:
                break
                
            current_qty = participants[pid]["quantity"]
            if adjustment < 0:  # Reduce quantity
                reduction = min(remaining_adjustment, current_qty - 5)  # Keep at least 5
                participants[pid]["quantity"] -= reduction
                remaining_adjustment -= reduction
            else:  # Increase quantity
                increase = min(remaining_adjustment, 10)  # Max increase 10
                participants[pid]["quantity"] += increase
                remaining_adjustment -= increase
    
    def _calculate_final_balances(self, participants: List[Dict], qualified_buyers: List[Tuple], 
                                 qualified_sellers: List[Tuple], clearing_price: int):
        """Calculate final coin and energy balances after auction"""
        
        # Create sets for quick lookup
        qualified_buyer_ids = {pid for pid, _ in qualified_buyers}
        qualified_seller_ids = {pid for pid, _ in qualified_sellers}
        
        for participant in participants:
            pid = participant["id"]
            role = participant["role"]
            quantity = participant["quantity"]
            
            if role == 0 and pid in qualified_buyer_ids:  # Qualified buyer
                # Buyer: pays coins, receives energy
                cost = quantity * clearing_price
                participant["out_coin"] = participant["in_coin"] - cost
                participant["out_energy"] = participant["in_energy"] + quantity
                
            elif role == 1 and pid in qualified_seller_ids:  # Qualified seller
                # Seller: receives coins, gives energy
                revenue = quantity * clearing_price
                participant["out_coin"] = participant["in_coin"] + revenue
                participant["out_energy"] = participant["in_energy"] - quantity
                
            # Unqualified participants keep their original balances
            # (out_coin and out_energy already set to in_coin and in_energy)
    
    def save_scenario(self, scenario: Dict, filename: str):
        """Save scenario to JSON file"""
        with open(filename, 'w') as f:
            json.dump(scenario, f, indent=2)
        print(f"Scenario saved to: {filename}")
    
    def print_summary(self, scenario: Dict):
        """Print a summary of the generated scenario"""
        print(f"\n{'='*50}")
        print(f"Generated Auction Scenario: {scenario['scenario_name']}")
        print(f"{'='*50}")
        print(f"Participants: {len(scenario['participants'])}")
        print(f"Expected Clearing Price: {scenario['expected_clearing_price']} coins/unit")
        print(f"Expected Energy Traded: {scenario['expected_total_energy_traded']} units")
        
        buyers = [p for p in scenario['participants'] if p['role'] == 0]
        sellers = [p for p in scenario['participants'] if p['role'] == 1]
        
        print(f"\nMarket Composition:")
        print(f"  Buyers: {len(buyers)}")
        print(f"  Sellers: {len(sellers)}")
        
        # Check which participants will actually trade
        clearing_price = scenario['expected_clearing_price']
        qualified_buyers = [b for b in buyers if b['price'] >= clearing_price]
        qualified_sellers = [s for s in sellers if s['price'] <= clearing_price]
        
        print(f"\nQualified Participants:")
        print(f"  Qualified Buyers: {len(qualified_buyers)} (bids ≥ {clearing_price})")
        print(f"  Qualified Sellers: {len(qualified_sellers)} (asks ≤ {clearing_price})")
        
        total_demand = sum(b['quantity'] for b in qualified_buyers)
        total_supply = sum(s['quantity'] for s in qualified_sellers)
        
        print(f"\nMarket Balance:")
        print(f"  Total Demand: {total_demand} units")
        print(f"  Total Supply: {total_supply} units")
        print(f"  Balance: {'Balanced' if total_demand == total_supply else 'Unbalanced'}")


def main():
    parser = argparse.ArgumentParser(description='Generate realistic auction scenarios for PPEM')
    parser.add_argument('participants', type=int, help='Number of participants')
    parser.add_argument('--output', '-o', type=str, help='Output filename (default: auction_scenario_N{participants}.json)')
    parser.add_argument('--name', type=str, help='Scenario name (default: Generated_PPEM_Auction_N{participants})')
    parser.add_argument('--seed', type=int, help='Random seed for reproducible results')
    parser.add_argument('--quiet', '-q', action='store_true', help='Suppress summary output')
    
    args = parser.parse_args()
    
    # Validate inputs
    if args.participants < 2:
        print("Error: Number of participants must be at least 2")
        sys.exit(1)
    
    # Set random seed if provided
    if args.seed:
        random.seed(args.seed)
        print(f"Using random seed: {args.seed}")
    
    # Set defaults
    output_file = args.output or f"auction_scenario_N{args.participants}.json"
    scenario_name = args.name or f"Generated_PPEM_Auction_N{args.participants}"
    
    # Generate scenario (fixed 50% buyer ratio)
    generator = AuctionScenarioGenerator(args.participants)
    scenario = generator.generate_scenario(scenario_name)
    
    # Save scenario
    generator.save_scenario(scenario, output_file)
    
    # Print summary unless quiet mode
    if not args.quiet:
        generator.print_summary(scenario)
    
    print(f"\nSuccessfully generated scenario with {args.participants} participants")
    print(f"Saved to: {output_file}")


if __name__ == "__main__":
    main() 