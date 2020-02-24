// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pow.h>

#include <arith_uint256.h>
#include <chain.h>
#include <primitives/block.h>
#include <uint256.h>
#include <util.h>

// Suggestion of another algorithm for nActualSpacing calculation:
// - sort the last 11 blocks (used in GetMetianTimePast function) according the block time
// - then calculate time between the median block and the block with the highest timestamp -> shortTime (distance 5 blocks)
// - calculate time between the timestamp of the top-block and the timestamp 23 blocks ago -> longTime (distance 22 blocks)
// - return an average of shortTime and longTime
int64_t CalcActualSpacing(const CBlockIndex* pindex)
{
    int64_t lastTime = pindex->GetBlockTime();
    int64_t sbta[11];	// Sorted Block Times Array
    for (int i=0; i<11; i++)
    {
        sbt[i] = pindex->GetBlockTime();
	pindex = pindex->pprev;    
    }
    std::sort(sbta, sbta+n); 
    int64_t shortTime = (sbta[10]-sbta[5])/5;
    for (int i=0; i<12; i++)
        pindex = pindex->pprev;
    int64_t longTime = (lastTime - pindex->GetBlockTime())/22;
    return ((shortTime+longTime)/2);
}

unsigned int GetNextWorkRequired(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params& params)
{
    unsigned int nProofOfWorkLimit = UintToArith256(params.powLimit).GetCompact();
    // Genesis block
    if (pindexLast == NULL)
        return nProofOfWorkLimit;
    // 1st block
    if (pindexLast->pprev == NULL)
	    return nProofOfWorkLimit;
    // 2nd block
    if (pindexLast->pprev->pprev == NULL)
	    return nProofOfWorkLimit;
    const CBlockIndex* pindexFirst = pindexLast->pprev;
    return CalculateNextWorkRequired(pindexLast, pindexFirst->GetBlockTime(), params);
}

unsigned int CalculateNextWorkRequired(const CBlockIndex* pindexLast, int64_t nFirstBlockTime, const Consensus::Params& params)
{
    if (params.fPowNoRetargeting)
        return pindexLast->nBits;
	
    // if (blockHeight < swapAlgoHeight)	            // !!!!!
    int64_t nActualSpacing = pindexLast->GetBlockTime() - nFirstBlockTime;
    // else nActualSpacing = CalcActualSpacing(pindexLast); // !!!!!
	
    // limit the adjustment
    if (nActualSpacing < params.nPowTargetSpacing/16)
	    nActualSpacing = params.nPowTargetSpacing/16;
    if (nActualSpacing > params.nPowTargetSpacing*16)
	    nActualSpacing = params.nPowTargetSpacing*16;
    // Retarget
    arith_uint256 bnNew;
    bnNew.SetCompact(pindexLast->nBits);
    const int64_t nInterval = 30;			// nTargetTimespan / nTargetSpacing = 30*60 / 60 = 30
    bnNew *= ((nInterval - 1) * params.nPowTargetSpacing + 2 * nActualSpacing);
    bnNew /= ((nInterval + 1) * params.nPowTargetSpacing);
    const arith_uint256 bnPowLimit = UintToArith256(params.powLimit);
    if (bnNew > bnPowLimit )
        bnNew = bnPowLimit;
    return bnNew.GetCompact();
}

bool CheckProofOfWork(uint256 hash, unsigned int nBits, const Consensus::Params& params)
{
    bool fNegative;
    bool fOverflow;
    arith_uint256 bnTarget;

    bnTarget.SetCompact(nBits, &fNegative, &fOverflow);

    // Check range
    if (fNegative || bnTarget == 0 || fOverflow || bnTarget > UintToArith256(params.powLimit))
        return false;

    // Check proof of work matches claimed amount
    if (UintToArith256(hash) > bnTarget)
        return false;

    return true;
}
