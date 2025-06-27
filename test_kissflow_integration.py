"""
Test script for Kissflow API integration
This script helps verify that the Kissflow API integration is working correctly
"""

import os
import sys
from datetime import datetime
from random import Random
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Add the current directory to the Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import the functions we want to test
from server import (
    get_identifier,
    find_aog_item_by_grant_id,
    update_aog_kyc_comments,
    send_identifier_to_kissflow
)


def test_environment_variables():
    """Test that all required Kissflow environment variables are set"""
    print("Testing environment variables...")
    
    required_vars = ['KISSFLOW_API_KEY', 'KISSFLOW_ACCOUNT_ID', 'KISSFLOW_PROCESS_ID']
    missing_vars = []
    
    for var in required_vars:
        value = os.getenv(var)
        if value:
            # Mask the value for security
            masked_value = value[:4] + '...' + value[-4:] if len(value) > 8 else '***'
            print(f"✓ {var}: {masked_value}")
        else:
            print(f"✗ {var}: NOT SET")
            missing_vars.append(var)
    
    if missing_vars:
        print(f"\nERROR: Missing environment variables: {', '.join(missing_vars)}")
        print("Please set these variables in your .env file")
        return False
    
    print("\nAll environment variables are set!")
    return True


def test_identifier_generation():
    """Test the identifier generation function"""
    print("\nTesting identifier generation...")
    
    # Test with default parameters
    identifier1 = get_identifier('legal')
    print(f"Generated identifier: {identifier1}")
    
    # Test with custom parameters
    custom_date = datetime(2025, 1, 15, 14, 30, 45)
    identifier2 = get_identifier('legal', now=custom_date, randint=1234)
    expected = 'legal:2025:01:15:14:30:45:1234'
    
    if identifier2 == expected:
        print(f"✓ Custom identifier matches expected: {identifier2}")
    else:
        print(f"✗ Custom identifier mismatch!")
        print(f"  Expected: {expected}")
        print(f"  Got: {identifier2}")
    
    return True


def test_find_aog_item(grant_id):
    """Test finding an AOG item by Grant ID"""
    print(f"\nTesting AOG item lookup for Grant ID: {grant_id}")
    
    try:
        item_id = find_aog_item_by_grant_id(grant_id)
        
        if item_id:
            print(f"✓ Found AOG item with ID: {item_id}")
            return item_id
        else:
            print(f"✗ No AOG item found for Grant ID: {grant_id}")
            return None
            
    except Exception as e:
        print(f"✗ Error finding AOG item: {str(e)}")
        return None


def test_update_kyc_comments(item_id, identifier):
    """Test updating the KYC_Comments field"""
    print(f"\nTesting KYC_Comments update...")
    print(f"Item ID: {item_id}")
    print(f"Identifier: {identifier}")
    
    try:
        success = update_aog_kyc_comments(item_id, identifier)
        
        if success:
            print("✓ Successfully updated KYC_Comments field")
            return True
        else:
            print("✗ Failed to update KYC_Comments field")
            return False
            
    except Exception as e:
        print(f"✗ Error updating KYC_Comments: {str(e)}")
        return False


def test_full_integration(grant_id):
    """Test the full integration flow"""
    print(f"\nTesting full integration flow for Grant ID: {grant_id}")
    
    # Generate a test identifier
    identifier = get_identifier('legal')
    print(f"Generated identifier: {identifier}")
    
    try:
        success = send_identifier_to_kissflow(grant_id, identifier)
        
        if success:
            print("✓ Full integration test passed!")
            print(f"  - Grant ID: {grant_id}")
            print(f"  - Identifier: {identifier}")
            print("  - Successfully updated in Kissflow")
            return True
        else:
            print("✗ Full integration test failed")
            return False
            
    except Exception as e:
        print(f"✗ Error in full integration: {str(e)}")
        return False


def main():
    """Main test function"""
    print("=" * 60)
    print("Kissflow Integration Test Suite")
    print("=" * 60)
    
    # Test 1: Environment variables
    if not test_environment_variables():
        print("\nCannot proceed without proper environment variables.")
        return
    
    # Test 2: Identifier generation
    test_identifier_generation()
    
    # Get Grant ID for testing
    print("\n" + "-" * 60)
    grant_id = input("Enter a Grant ID to test (or press Enter to skip API tests): ").strip()
    
    if not grant_id:
        print("Skipping API tests.")
        return
    
    # Test 3: Find AOG item
    item_id = test_find_aog_item(grant_id)
    
    if item_id:
        # Test 4: Update KYC Comments
        test_identifier = f"TEST:{get_identifier('legal')}"
        test_update_kyc_comments(item_id, test_identifier)
    
    # Test 5: Full integration
    print("\n" + "-" * 60)
    test_full_integration(grant_id)
    
    print("\n" + "=" * 60)
    print("Test suite completed!")
    print("=" * 60)


if __name__ == "__main__":
    main()
