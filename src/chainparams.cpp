// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Copyright (c) 2019 The EarthCoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <consensus/merkle.h>

#include <tinyformat.h>
#include <util.h>
#include <utilstrencodings.h>

#include <assert.h>

#include <chainparamsseeds.h>

static CBlock CreateGenesisBlock(const char* pszTimestamp, const CScript& genesisOutputScript, uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    CMutableTransaction txNew;
    txNew.nVersion = 2;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}

/**
 * Build the genesis block. Note that the output of its generation
 * transaction cannot be spent since it did not originally exist in the
 * database.
 *
 * CBlock(hash=000000000019d6, ver=1, hashPrevBlock=00000000000000, hashMerkleRoot=4a5e1e, nTime=1231006505, nBits=1d00ffff, nNonce=2083236893, vtx=1)
 *   CTransaction(hash=4a5e1e, ver=1, vin.size=1, vout.size=1, nLockTime=0)
 *     CTxIn(COutPoint(000000, -1), coinbase 04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73)
 *     CTxOut(nValue=50.00000000, scriptPubKey=0x5F1DF16B2B704C8A578D0B)
 *   vMerkleTree: 4a5e1e
 */
static CBlock CreateGenesisBlock(uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    const char* pszTimestamp = " December 19, 2013 \x97 Arrest, strip-search of Indian diplomat in New York triggers uproar.";
    const CScript genesisOutputScript = CScript() << ParseHex("04dcba12349012341234900abcd12223abcd455abcd77788abcd000000aaaaabbbbbcccccdddddeeeeeff00ff00ff00ff001234567890abcdef0022446688abc11") << OP_CHECKSIG;
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nBits, nVersion, genesisReward);
}

void CChainParams::UpdateVersionBitsParameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
{
    consensus.vDeployments[d].nStartTime = nStartTime;
    consensus.vDeployments[d].nTimeout = nTimeout;
}

/**
 * Main network
 */
/**
 * What makes a good checkpoint block?
 * + Is surrounded by blocks with reasonable timestamps
 *   (no blocks before with a timestamp after, none after with
 *    timestamp before)
 * + Contains no strange transactions
 */

class CMainParams : public CChainParams {
public:
    CMainParams() {
        strNetworkID = "main";
        consensus.nSubsidyHalvingInterval = 525600;
        consensus.BIP16Height = 0; // October 1, 2012 it was before EAC genesis // int64 nBIP16SwitchTime = 1349049600
        consensus.BIP34Height = 710000;      // EAC dev note: after this height only block version 2 are allowed
        consensus.BIP34Hash = uint256S("fa09d204a83a768ed5a7c8d441fa62f2043abf420cff1226c7b4329aeb9d51cf");
        consensus.BIP65Height = 99999999; // EAC dev note: disabled for now     // OP_CHECKLOCKTIMEVERIFY
        consensus.BIP66Height = 99999999; // EAC dev note: disabled for now
        consensus.powLimit = uint256S("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"); 
        consensus.nPowTargetTimespan = 30 * 60;  // 30 minutes
        consensus.nPowTargetSpacing = 60;        // 60 seconds
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 6048; // 75% of 8064
        consensus.nMinerConfirmationWindow = 8064; // nPowTargetTimespan / nPowTargetSpacing * 4
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; // December 31, 2008

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 1485561600; // January 28, 2017
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 1517356801; // January 31st, 2018

        // Deployment of SegWit (BIP141, BIP143, and BIP147)
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = 1485561600; // January 28, 2017
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = 1517356801; // January 31st, 2018

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x0000000000000000000000000000000000000000000000004ea75c690519ca29");   // block 2458500

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x98b01e772f0ca3b3ac875857e4f3b6571f8f18b8b896d0cb2feefeca90b69583"); //2242222  // ?????

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 32-bit integer with any alignment.
         */
        pchMessageStart[0] = 0xc0;
        pchMessageStart[1] = 0xdb;
        pchMessageStart[2] = 0xf1;
        pchMessageStart[3] = 0xfd;
        nDefaultPort = 35677;
        nPruneAfterHeight = 100000;

        genesis = CreateGenesisBlock(1386746168, 12468024, 0x1e0ffff0, 1, 0 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x21717d4df403301c0538f1cb9af718e483ad06728bbcd8cc6c9511e2f9146ced"));
        assert(genesis.hashMerkleRoot == uint256S("0x13757c3610411891452ac1f04d7f81946339b0e5b5aba216e6646e81805c4bb1"));

        // Note that of those which support the service bits prefix, most only support a subset of
        // possible options.
        // This is fine at runtime as we'll fall back to using them as a oneshot if they don't support the
        // service bits we want, but we should get them updated to support all service bits wanted by any
        // release ASAP to avoid it where possible.
//        vSeeds.emplace_back("seed-a.earthcoin.loshan.co.uk");
//        vSeeds.emplace_back("dnsseed.thrasher.io");
//        vSeeds.emplace_back("dnsseed.earthcointools.com");
//        vSeeds.emplace_back("dnsseed.earthcoinpool.org");
//        vSeeds.emplace_back("dnsseed.koin-project.com");

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,93);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,5);
        base58Prefixes[SCRIPT_ADDRESS2] = std::vector<unsigned char>(1,33);  // segwit addresses will start with E
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,221);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x88, 0xB2, 0x1E};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x88, 0xAD, 0xE4};

        bech32_hrp = "eac";

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_main, pnSeed6_main + ARRAYLEN(pnSeed6_main));

        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;

        checkpointData = {
            {
                {    100, uint256S("0xc3d91cb4726610d422f8652a5a7cc21bd42e1b8009c00462081c81316d9abad6")},
                {  10000, uint256S("0x7b50ea3b42e613e65ec2aca6797a5780e1c545a617e4a610577fb4b040f0035b")},
                {  30000, uint256S("0x43e2fe7c700191ddfabe2cd09dfd3fc9eb6331f3c19e59b3e4a87cfa88cac543")},
                {  50000, uint256S("0x6a4f705b7a34de7dc1b6573b3595fde05c7b4303b35ede20a3b945244adc6c70")},
                {  69500, uint256S("0x8387b49853928fc67d8b8421fd9214184db590eeecd90a200c9d902d8b42e11f")},
                {  80000, uint256S("0xa7d7ac0b4b1f5eb56b50ad0693c47f47863b8df81f17514bcb5e59c0a4074eba")},
                {  91000, uint256S("0x3f135e0e06ae032de5437ae2b981e3ab84c7d22310224a6e53c6e6e769e8f8f0")},
                { 101000, uint256S("0xba5948ef9fce38887df24c54366121437d336bd67a4332508248def0032c5d6e")},
                { 111000, uint256S("0xbb9cc6e2d9da343774dc4b49be417731991b90ef53a7fa7eb669cce237223c37")},
                { 121000, uint256S("0x1d286956120cf256bed13bcc1f5fe79a98347c80f2225ded92bbbdfc1147b5f5")},
                { 136000, uint256S("0xb7c7416c40425bc7976c7b6b87734e2fb84855eecd30e3e9673caf8c7f599b5c")},
                { 153000, uint256S("0x9f31abd27721e7eb2b58c0a61a117c324a3a6b8f45c82e8963b1bd14166f6510")},
                { 161000, uint256S("0xf7a9069c705516f60878bf6da9bac02c12d0d8984cb90bce03fe34842ba7eb3d")},
                { 170000, uint256S("0x827d5ce5ed69153deacab9a2d3c35a7b33cdaa397a6a4a540d538b765182f234")},
                { 181000, uint256S("0x69fa48e8b9231f101df79c5b3174feb70bf6da11d88a4ce879a7c9ecb799f46d")},
                { 191000, uint256S("0x80a9ea6b375312c376de880b6958459973a95be1dcbf28db1731452a59ef9750")},
                { 200000, uint256S("0x003a4cb3bf206cfc23b9477e1c433280ae1b3393a21aa858aa322e8402204cd0")},
                { 220000, uint256S("0xbed97c09983d1ee14d5f925c31dc4245b6c9d66af4fdadcf973465cb265b52c3")},
                { 240000, uint256S("0xd4e782aae21f551d4a8d7756eb92dfa2cb23d1ede58162382b3bbced4fbee518")},
                { 260000, uint256S("0xdfaef016341fab642190a6656b6c52efbdb43ce8a590bace86793f3c1b1276be")},
                { 280000, uint256S("0x6b836125e431d3fd31ef55f5fbbdfdadc4d9b98b11db5ee0b7ac8f1f8c3ede32")},
                { 301000, uint256S("0xc557d7363393148a630a3fda46ca380a202fe82fa594c5e57f88fbece755bb05")},
                { 324000, uint256S("0x8f6cb33fd75e327eb1a1d90b13ba2124e077b4cc5240bc7ec8039aee8a345e85")},
                { 347000, uint256S("0xf4bd9894306981ca4c20cdbf0bbd9e9832696701f5b3d3a840d026b893db7337")},
                { 383000, uint256S("0xd902cf21480851c35844b0744ea72c1bc2d9318e87a7de63a5e3e3854331a39c")},
                { 401000, uint256S("0xe43417eb3b583fd28dfbfb38c65763d990b4c370066ac615a08c4c5c3910ebc9")},
                { 420000, uint256S("0x76e0de5adb117e12e85beb264c45e768e47d1720d72a49a24daab57493e07a04")},
                { 440000, uint256S("0xbbc6051554e936d0a18adddb95064b16a001ce164d061fb399f26416ce7860f9")},
                { 461000, uint256S("0xa60d67991b4963efee5b102c281755afde28803b9bc0b647f0cbc2120b35185b")},
                { 480000, uint256S("0xd88e6f5e77a8cb4bcb883168f357a94db31203f1977a15d90b6f6d4c2edebbbb")},
                { 500000, uint256S("0xa2989da9f8e785f7040c2e2dfc0177babbf736cfad9f2b401656fea4c3c7c9db")},
                { 510000, uint256S("0x7646ee1a99843f1e303d85e14c58dbf2bd65b393b273b379de14534743111b72")},
                { 520000, uint256S("0x114f6c2065ad5e668b901dd5ed5e9d302d6153f8e38381fbfd44485d7d499e10")},
                { 540000, uint256S("0xd7480699ff87574bfad0038b8697f9bc4df5f0cba31058a637eefbc94e402761")},
                { 600000, uint256S("0x85ac8dbbba7a870a45740677be5f35114cb3b70f56d1c93cc2aaf415629037e7")},
                { 700000, uint256S("0x450af2f828cdfb29be40d644d39a0858b29fe05b556946db31a7c365cffed705")},
                { 800001, uint256S("0xa6d915a25e905d1329e482aac91228b168de6e6efb3838df16c21c3ac3a82ea2")},
                { 900000, uint256S("0x7854a46edbdc4311006a9fd27ae601bb1ebd22fc5e8d6f1757e15237080a545b")},
                {1000000, uint256S("0xec070022a4fe9b450e02edd08c6ed355047bc8e65ef05e881b51c212d7c0fe95")},
                {1010001, uint256S("0xa2cb82b4ae04854108b18c502f1b33e18c6f69b9d4407e8aa205a23242cd4daf")},
                {1050000, uint256S("0x3369fa16394aa222736793fd3fd50d7f7a34d5b1ff67b344eaba269daab28a68")},
                {1060000, uint256S("0x44e3b2bfbfb9eef5ef34df447c9ea4c4912b8a3819c2c56dfd0dc02db8a84347")},
                {1100000, uint256S("0x4173031420285636eeecfab94e4e62e3a3cf6e144b97b2cc3622c683e09102f0")},
                {1394462, uint256S("0xef308b7f477903acd8f300e6f0684c4888ce28c491fc32c1c469bfba6abf091b")},
                {1400000, uint256S("0x4bc57c3a57cc977db9f3bd6a095f51c0c7cc9c30fa8554505fa8f8e33d9f2b80")},
                {1410000, uint256S("0x7512574ec717d46a90b8c36fd923ef819fdc298b8e4be57be631519662f0db59")},
                {1573741, uint256S("0x6e4dacfd1684e71a178f29f3e9c714d264e6d385f64c31cdbe532b3204ce4e1d")},
                {1574000, uint256S("0xcef389868efd7785b977eb86527e8049a2a5ea472a6ed9bfc0741c6d6b39234b")},
                {1579000, uint256S("0x12cb8ae28107d99f4ba24465b9abf21f98fe855d9b09449cf5c8ed98120829c1")},
                {1589000, uint256S("0x479746c27e323e233e58af6024bb7b9727a26bc0114c26ff537469e6ada105e1")},
                {1600000, uint256S("0xf44cbdcb21fc7716947f763ccca5de5b02ffff7f14beafef0a7486067f6777fa")},
                {1650000, uint256S("0x70caabb0720c95f67a02eabfde27253eaa8698dc6ea5716631890876b9df421a")},
                {1700000, uint256S("0x691eb62d25a0961e81f1a8427b8c21e01ade5befe4a94be5826f49cfecc070a0")},
                {1750000, uint256S("0x8971f1790e58c6de0ea2854872c6ad03752b65567ab8e5c8458ae4a6eb9fb783")},
                {1766666, uint256S("0xffb7d30ec4d20cae926af05252dc39dbc433b068a0807a8f0dfa63521caca6f0")},
                {1888888, uint256S("0x89530dba778db5a540aac6b7b8659cee8909ba445fa5a54ba3023e98e045692d")},
                {1892222, uint256S("0x685a23cfa75e4e084f32b6a4ae09b3113c9509d84ce0559813627d462df6db88")},
                {2227008, uint256S("0x23eb6ca0fc87c887485a1417364dae6c3ae5cc4801c6eef8fc2b6bb83cdf9013")},
                {2242222, uint256S("0x98b01e772f0ca3b3ac875857e4f3b6571f8f18b8b896d0cb2feefeca90b69583")},
                {2460000, uint256S("0x13dcc432b541f34539f0582ebad2ab045db399e58404385ee1e24b4713346a5b")},
            }
        };

        chainTxData = ChainTxData{
            // Data from rpc: getchaintxstats 4096 a601455787cb65ffc325dda4751a99cf01d1567799ec4b04f45bb05f9ef0cbde
            /* nTime    */ 1557352598,
            /* nTxCount */ 3860794,
            /* dTxRate  */ 7200.0
        };

        /* disable fallback fee on mainnet */
        m_fallback_fee_enabled = true;
    }
};

/**
 * Testnet (v3)
 */
class CTestNetParams : public CChainParams {
public:
    CTestNetParams() {
        strNetworkID = "test";
        consensus.nSubsidyHalvingInterval = 525600;
        consensus.BIP16Height = 0; // always enforce P2SH BIP16 on testnet
        consensus.BIP34Height = 76;
        consensus.BIP34Hash = uint256S("8075c771ed8b495ffd943980a95f702ab34fce3c8c54e379548bda33cc8c0573");
        consensus.BIP65Height = 76; // 8075c771ed8b495ffd943980a95f702ab34fce3c8c54e379548bda33cc8c0573
        consensus.BIP66Height = 76; // 8075c771ed8b495ffd943980a95f702ab34fce3c8c54e379548bda33cc8c0573
        consensus.powLimit = uint256S("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 30 * 60; // 3.5 days
        consensus.nPowTargetSpacing = 60;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1512; // 75% for testchains
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; // December 31, 2008

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 1483228800; // January 1, 2017
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 1517356801; // January 31st, 2018

        // Deployment of SegWit (BIP141, BIP143, and BIP147)
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = 1483228800; // January 1, 2017
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = 1517356801; // January 31st, 2018

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x14b1da80b3d734d36a4a2be97ed2c9d49e79c47213d5bcc15b475a1115d28918"); //0

        pchMessageStart[0] = 0xfd;
        pchMessageStart[1] = 0xc2;
        pchMessageStart[2] = 0xb6;
        pchMessageStart[3] = 0xf1;
        nDefaultPort = 25677;
        nPruneAfterHeight = 1000;

        genesis = CreateGenesisBlock(1386746169, 12468025, 0x1e0ffff0, 1, 0 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x14b1da80b3d734d36a4a2be97ed2c9d49e79c47213d5bcc15b475a1115d28918"));
        assert(genesis.hashMerkleRoot == uint256S("0x13757c3610411891452ac1f04d7f81946339b0e5b5aba216e6646e81805c4bb1"));

        vFixedSeeds.clear();
        vSeeds.clear();
        // nodes with support for servicebits filtering should be at the top
        //vSeeds.emplace_back("testnet-seed.earthcointools.com");
        //vSeeds.emplace_back("seed-b.earthcoin.loshan.co.uk");
        //vSeeds.emplace_back("dnsseed-testnet.thrasher.io");

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196);
        base58Prefixes[SCRIPT_ADDRESS2] = std::vector<unsigned char>(1,58);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        bech32_hrp = "teac";

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_test, pnSeed6_test + ARRAYLEN(pnSeed6_test));

        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        fMineBlocksOnDemand = false;

        checkpointData = (CCheckpointData) {
            {
                {0, uint256S("0x14b1da80b3d734d36a4a2be97ed2c9d49e79c47213d5bcc15b475a1115d28918")},
            }
        };

        chainTxData = ChainTxData{
            // Data from rpc: getchaintxstats 4096 438b7e1c86f58b4e62e8cf2d0f9f256e3dddaebc5d1cc568e633a38e0db6c025
            /* nTime    */ 1386746169,
            /* nTxCount */ 0,
            /* dTxRate  */ 0.0
        };

        /* enable fallback fee on testnet */
        m_fallback_fee_enabled = true;
    }
};

/**
 * Regression test
 */
class CRegTestParams : public CChainParams {
public:
    CRegTestParams() {
        strNetworkID = "regtest";
        consensus.nSubsidyHalvingInterval = 525600;
        consensus.BIP16Height = 0; // always enforce P2SH BIP16 on regtest
        consensus.BIP34Height = 100000000; // BIP34 has not activated on regtest (far in the future so block v1 are not rejected in tests)
        consensus.BIP34Hash = uint256();
        consensus.BIP65Height = 1351; // BIP65 activated on regtest (Used in rpc activation tests)
        consensus.BIP66Height = 1251; // BIP66 activated on regtest (Used in rpc activation tests)
        consensus.powLimit = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 30 * 60; 
        consensus.nPowTargetSpacing = 60;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = true;
        consensus.nRuleChangeActivationThreshold = 108; // 75% for testchains
        consensus.nMinerConfirmationWindow = 144; // Faster than normal for regtest (144 instead of 2016)
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x00");

        pchMessageStart[0] = 0x64;
        pchMessageStart[1] = 0xa4;
        pchMessageStart[2] = 0x61;
        pchMessageStart[3] = 0xb0;
        nDefaultPort = 45677;
        nPruneAfterHeight = 1000;

        genesis = CreateGenesisBlock(1386746169, 12468025, 0x1e0ffff0, 1, 0 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x14b1da80b3d734d36a4a2be97ed2c9d49e79c47213d5bcc15b475a1115d28918"));
        assert(genesis.hashMerkleRoot == uint256S("0x13757c3610411891452ac1f04d7f81946339b0e5b5aba216e6646e81805c4bb1"));

        vFixedSeeds.clear(); //!< Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();      //!< Regtest mode doesn't have any DNS seeds.

        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = true; 

        checkpointData = {
            {
                {0, uint256S("0x14b1da80b3d734d36a4a2be97ed2c9d49e79c47213d5bcc15b475a1115d28918")},
            }
        };

        chainTxData = ChainTxData{
            1386746170,
            0,
            0.0
        };

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196);
        base58Prefixes[SCRIPT_ADDRESS2] = std::vector<unsigned char>(1,58);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        bech32_hrp = "reac";

        /* enable fallback fee on regtest */
        m_fallback_fee_enabled = true;
    }
};

static std::unique_ptr<CChainParams> globalChainParams;

const CChainParams &Params() {
    assert(globalChainParams);
    return *globalChainParams;
}

std::unique_ptr<CChainParams> CreateChainParams(const std::string& chain)
{
    if (chain == CBaseChainParams::MAIN)
        return std::unique_ptr<CChainParams>(new CMainParams());
    else if (chain == CBaseChainParams::TESTNET)
        return std::unique_ptr<CChainParams>(new CTestNetParams());
    else if (chain == CBaseChainParams::REGTEST)
        return std::unique_ptr<CChainParams>(new CRegTestParams());
    throw std::runtime_error(strprintf("%s: Unknown chain %s.", __func__, chain));
}

void SelectParams(const std::string& network)
{
    SelectBaseParams(network);
    globalChainParams = CreateChainParams(network);
}

void UpdateVersionBitsParameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
{
    globalChainParams->UpdateVersionBitsParameters(d, nStartTime, nTimeout);
}
