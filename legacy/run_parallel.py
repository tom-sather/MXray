#!/usr/bin/env python3
"""
Parallel Domain Analyzer Runner

This script allows you to run multiple instances of the domain analyzer in parallel
to process different files simultaneously.

Usage:
    python run_parallel.py file1.csv file2.csv file3.txt
    python run_parallel.py --merge output1.csv output2.csv --final merged_results.csv
"""

import asyncio
import subprocess
import sys
import os
import time
from typing import List
import argparse

def run_single_analysis(input_file: str, file_type: str = 'txt') -> str:
    """Run a single analysis process and return the output file path."""
    print(f"🚀 Starting analysis for: {input_file}")
    
    # Run the domain analyzer as a subprocess
    cmd = [sys.executable, 'swissarmydomain.py', input_file, file_type]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        print(f"✅ Completed analysis for: {input_file}")
        
        # Extract output filename from the output
        for line in result.stdout.split('\n'):
            if 'Analysis will be written to:' in line:
                output_file = line.split(': ')[1].strip()
                return output_file
        
        return None
    except subprocess.CalledProcessError as e:
        print(f"❌ Error processing {input_file}: {e}")
        print(f"   Error output: {e.stderr}")
        return None

def run_parallel_analysis(input_files: List[str], file_types: List[str] = None) -> List[str]:
    """Run multiple analyses in parallel."""
    if file_types is None:
        file_types = ['txt'] * len(input_files)
    
    print(f"🔄 Starting parallel analysis of {len(input_files)} files...")
    print(f"   Files: {input_files}")
    print(f"   Types: {file_types}")
    
    # Create tasks for all files
    tasks = []
    for input_file, file_type in zip(input_files, file_types):
        task = asyncio.create_task(
            asyncio.to_thread(run_single_analysis, input_file, file_type)
        )
        tasks.append(task)
    
    # Run all tasks concurrently
    results = asyncio.gather(*tasks, return_exceptions=True)
    return results

def merge_results(output_files: List[str], final_output: str) -> int:
    """Merge multiple output files into one."""
    from swissarmydomain import merge_parallel_outputs
    
    return merge_parallel_outputs(output_files, final_output)

async def main():
    parser = argparse.ArgumentParser(description='Run parallel domain analysis')
    parser.add_argument('files', nargs='*', help='Input files to process')
    parser.add_argument('--types', nargs='*', help='File types (txt/csv) for each file')
    parser.add_argument('--merge', nargs='*', help='Output files to merge')
    parser.add_argument('--final', help='Final merged output file')
    
    args = parser.parse_args()
    
    if args.merge and args.final:
        # Merge mode
        print("🔗 Merging existing result files...")
        count = merge_results(args.merge, args.final)
        print(f"✅ Merged {count} results into {args.final}")
        return
    
    if not args.files:
        print("❌ No input files specified")
        parser.print_help()
        return
    
    # Determine file types
    if args.types:
        file_types = args.types
    else:
        file_types = []
        for file in args.files:
            if file.lower().endswith('.csv'):
                file_types.append('csv')
            else:
                file_types.append('txt')
    
    # Ensure we have the right number of file types
    while len(file_types) < len(args.files):
        file_types.append('txt')
    
    # Run parallel analysis
    start_time = time.time()
    output_files = await run_parallel_analysis(args.files, file_types)
    
    # Filter out None results (failed processes)
    successful_outputs = [f for f in output_files if f is not None]
    
    elapsed_time = time.time() - start_time
    
    print(f"\n🎉 Parallel analysis complete!")
    print(f"   ✅ Successful: {len(successful_outputs)}/{len(args.files)}")
    print(f"   ⏱️  Total time: {elapsed_time:.2f} seconds")
    
    if successful_outputs:
        print(f"\n📄 Output files:")
        for output_file in successful_outputs:
            print(f"   {output_file}")
        
        # Offer to merge results
        if len(successful_outputs) > 1:
            print(f"\n💡 To merge all results, run:")
            print(f"   python run_parallel.py --merge {' '.join(successful_outputs)} --final merged_results.csv")

if __name__ == "__main__":
    asyncio.run(main())
