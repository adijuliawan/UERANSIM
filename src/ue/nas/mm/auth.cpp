//
// This file is a part of UERANSIM project.
// Copyright (c) 2023 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

#include "mm.hpp"

#include <lib/nas/utils.hpp>
#include <ue/nas/keys.hpp>

#include "oqs/oqs.h"
#include "oqs/sha3.h"

namespace nr::ue
{

void NasMm::receiveAuthenticationRequest(const nas::AuthenticationRequest &msg)
{
    m_logger->debug("Authentication Request received");

    if (!m_usim->isValid())
    {
        m_logger->warn("Authentication request is ignored. USIM is invalid");
        return;
    }

    m_timers->t3520.start();

    if (msg.eapMessage.has_value())
        receiveAuthenticationRequestEap(msg);
    else
        receiveAuthenticationRequest5gAka(msg);
}

void NasMm::receiveAuthenticationRequestEap(const nas::AuthenticationRequest &msg)
{
    Plmn currentPlmn = m_base->shCtx.getCurrentPlmn();
    if (!currentPlmn.hasValue())
        return;

    auto sendEapFailure = [this](std::unique_ptr<eap::Eap> &&eap) {
        // Clear RAND and RES* stored in volatile memory
        m_usim->m_rand = {};

        m_usim->m_resStar = {};

        // Stop T3516 if running
        m_timers->t3516.stop();

        nas::AuthenticationResponse resp;
        resp.eapMessage = nas::IEEapMessage{};
        resp.eapMessage->eap = std::move(eap);
        sendNasMessage(resp);
    };

    auto sendAuthFailure = [this](nas::EMmCause cause) {
        m_logger->err("Sending Authentication Failure with cause [%s]", nas::utils::EnumToString(cause));

        // Clear RAND and RES* stored in volatile memory
        m_usim->m_rand = {};
        m_usim->m_resStar = {};

        // Stop T3516 if running
        m_timers->t3516.stop();

        // Send Authentication Failure
        nas::AuthenticationFailure resp{};
        resp.mmCause.value = cause;
        sendNasMessage(resp);
    };

    // ========================== Check the received message syntactically ==========================

    if (!msg.eapMessage.has_value())
    {
        sendMmStatus(nas::EMmCause::SEMANTICALLY_INCORRECT_MESSAGE);
        return;
    }

    if (msg.eapMessage->eap->eapType != eap::EEapType::EAP_AKA_PRIME)
    {
        sendMmStatus(nas::EMmCause::SEMANTICALLY_INCORRECT_MESSAGE);
        return;
    }

    auto &receivedEap = (const eap::EapAkaPrime &)*msg.eapMessage->eap;

    if (receivedEap.subType != eap::ESubType::AKA_CHALLENGE)
    {
        sendMmStatus(nas::EMmCause::SEMANTICALLY_INCORRECT_MESSAGE);
        return;
    }

    // ================================ Check the received parameters syntactically ================================

    auto receivedRand = receivedEap.attributes.getRand();
    auto receivedMac = receivedEap.attributes.getMac();
    auto receivedAutn = receivedEap.attributes.getAutn();
    

    //check if FS extension is used 
    auto receivedPubECDHE = receivedEap.attributes.getPubECDHE();
    auto receivedPubHybrid = receivedEap.attributes.getPubHybrid();
    auto receivedPubKem = receivedEap.attributes.getPubKem();

    m_logger->debug("[EAP-AKA-PRIME][PQC][ML-KEM] OQS_KEM_ml_kem_768_length_public_key [%d]",OQS_KEM_ml_kem_768_length_public_key);
    m_logger->debug("[EAP-AKA-PRIME][PQC][ML-KEM] OQS_KEM_ml_kem_768_length_secret_key [%d]",OQS_KEM_ml_kem_768_length_secret_key);
    m_logger->debug("[EAP-AKA-PRIME][PQC][ML-KEM] OQS_KEM_ml_kem_768_length_ciphertext [%d]",OQS_KEM_ml_kem_768_length_ciphertext);
    m_logger->debug("[EAP-AKA-PRIME][PQC][ML-KEM] OQS_KEM_ml_kem_768_length_shared_secret [%d]",OQS_KEM_ml_kem_768_length_shared_secret);
    m_logger->debug("[EAP-AKA-PRIME][PQC][ML-KEM] OQS_KEM_ml_kem_768_length_shared_secret [%d]",OQS_KEM_ml_kem_768_length_shared_secret);

    m_logger->debug("[EAP-AKA-PRIME] AT_RAND [%s]",receivedRand.toHexString().c_str());
    m_logger->debug("[EAP-AKA-PRIME] AT_AUTN [%s]",receivedAutn.toHexString().c_str());
    m_logger->debug("[EAP-AKA-PRIME] AT_MAC  [%s]",receivedMac.toHexString().c_str());
    m_logger->debug("[EAP-AKA-PRIME][FS] AT_PUB_ECDHE  [%s]",receivedPubECDHE.toHexString().c_str());
    m_logger->debug("[EAP-AKA-PRIME][HPQC] AT_PUB_HYBRID  [%s]",receivedPubHybrid.toHexString().c_str());
    m_logger->debug("[EAP-AKA-PRIME][PQC] AT_PUB_KEM  [%s]",receivedPubKem.toHexString().c_str());
    m_logger->debug("[EAP-AKA-PRIME][PQC] AT_PUB_KEM Length  [%d]",receivedPubKem.length());

    if (receivedRand.length() != 16 || receivedAutn.length() != 16 || receivedMac.length() != 16)
    {
        sendMmStatus(nas::EMmCause::SEMANTICALLY_INCORRECT_MESSAGE);
        return;
    }

    // =================================== Check the received KDF and KDF_INPUT ===================================

    if (receivedEap.attributes.getKdf() != 1)
    {
        m_logger->err("EAP AKA' Authentication Reject, received AT_KDF is not valid");
        if (networkFailingTheAuthCheck(true))
            return;
        m_timers->t3520.start();
        sendEapFailure(std::make_unique<eap::EapAkaPrime>(eap::ECode::RESPONSE, receivedEap.id,
                                                          eap::ESubType::AKA_AUTHENTICATION_REJECT));
        return;
    }

    auto snn = keys::ConstructServingNetworkName(currentPlmn);

    if (receivedEap.attributes.getKdfInput() != OctetString::FromAscii(snn))
    {
        m_logger->err("EAP AKA' Authentication Reject, received AT_KDF_INPUT is not valid");

        sendEapFailure(std::make_unique<eap::EapAkaPrime>(eap::ECode::RESPONSE, receivedEap.id,
                                                          eap::ESubType::AKA_AUTHENTICATION_REJECT));
        return;
    }

    // =================================== Check the received ngKSI ===================================

    if (msg.ngKSI.tsc == nas::ETypeOfSecurityContext::MAPPED_SECURITY_CONTEXT)
    {
        m_logger->err("Mapped security context not supported");
        sendAuthFailure(nas::EMmCause::UNSPECIFIED_PROTOCOL_ERROR);
        return;
    }

    if (msg.ngKSI.ksi == nas::IENasKeySetIdentifier::NOT_AVAILABLE_OR_RESERVED)
    {
        m_logger->err("Invalid ngKSI value received");
        sendAuthFailure(nas::EMmCause::UNSPECIFIED_PROTOCOL_ERROR);
        return;
    }

    if ((m_usim->m_currentNsCtx && m_usim->m_currentNsCtx->ngKsi == msg.ngKSI.ksi) ||
        (m_usim->m_nonCurrentNsCtx && m_usim->m_nonCurrentNsCtx->ngKsi == msg.ngKSI.ksi))
    {
        if (networkFailingTheAuthCheck(true))
            return;

        m_timers->t3520.start();
        sendAuthFailure(nas::EMmCause::NGKSI_ALREADY_IN_USE);
        return;
    }

    // =================================== Check the received AUTN ===================================

    auto autnCheck = validateAutn(receivedRand, receivedAutn);
    m_timers->t3516.start();

    if (autnCheck == EAutnValidationRes::OK)
    {
        // Calculate milenage
        auto milenage = calculateMilenage(m_usim->m_sqnMng->getSqn(), receivedRand, false);
        auto sqnXorAk = OctetString::Xor(m_usim->m_sqnMng->getSqn(), milenage.ak);
        auto ckPrimeIkPrime = keys::CalculateCkPrimeIkPrime(milenage.ck, milenage.ik, snn, sqnXorAk);
        auto &ckPrime = ckPrimeIkPrime.first;
        auto &ikPrime = ckPrimeIkPrime.second;

        
        m_logger->debug("[EAP-AKA-PRIME] CK_PRIME [%s]",ckPrime.toHexString().c_str());
        m_logger->debug("[EAP-AKA-PRIME] IK_PRIME [%s]",ikPrime.toHexString().c_str());
        m_logger->debug("[EAP-AKA-PRIME] AT_RES [%s]",milenage.res.toHexString().c_str());

        auto mk = keys::CalculateMk(ckPrime, ikPrime, m_base->config->supi.value());
        auto kencr = mk.subCopy(0,16);
        auto kaut = mk.subCopy(16, 32);

        m_logger->debug("[EAP-AKA-PRIME] MK [%s]",mk.toHexString().c_str());
        m_logger->debug("[EAP-AKA-PRIME] K_ENCR [%s]",kencr.toHexString().c_str());
        m_logger->debug("[EAP-AKA-PRIME] K_AUT [%s]",kaut.toHexString().c_str());

        // Check the received AT_MAC
        auto expectedMac = keys::CalculateMacForEapAkaPrime(kaut, receivedEap);
        /*
        if (expectedMac != receivedMac)
        {
            m_logger->err("AT_MAC failure in EAP AKA'. expected: %s received: %s", expectedMac.toHexString().c_str(),
                          receivedMac.toHexString().c_str());
            if (networkFailingTheAuthCheck(true))
                return;
            m_timers->t3520.start();

            auto eap = std::make_unique<eap::EapAkaPrime>(eap::ECode::RESPONSE, receivedEap.id,
                                                          eap::ESubType::AKA_CLIENT_ERROR);
            eap->attributes.putClientErrorCode(0);
            sendEapFailure(std::move(eap));
            return;
        }
        */

        // Check if UE want to participate in FS extension or HPQC 
        if(receivedPubECDHE.length()==32){
            m_logger->debug("[EAP-AKA-PRIME-FS]");

            std::string name("Seed for x25519 generation");
            std::string seed;
            Random rnd = Random::Mixed(name);
            int intLength = sizeof(int32_t);

            for (int i=0; i < (X25519_KEY_SIZE/intLength); i++)
            {
                seed = seed + utils::IntToHex(rnd.nextI());
            }
            OctetString randomSeed = OctetString::FromHex(seed);
            uint8_t privateKey[X25519_KEY_SIZE];
            uint8_t publicKey[X25519_KEY_SIZE];    
            compact_x25519_keygen(privateKey,publicKey, randomSeed.data());
            OctetString uePrivateKey = OctetString::FromArray(privateKey, X25519_KEY_SIZE);
            OctetString uePublicKey = OctetString::FromArray(publicKey, X25519_KEY_SIZE);

            OctetString shared;
            shared.appendPadding(32);
            compact_x25519_shared(shared.data(), uePrivateKey.data(), receivedPubECDHE.data());

            m_logger->debug("[EAP-AKA-PRIME-FS] Public Key HN [%s]",receivedPubECDHE.toHexString().c_str());
            m_logger->debug("[EAP-AKA-PRIME-FS] Private Key UE [%s]",uePrivateKey.toHexString().c_str());
            m_logger->debug("[EAP-AKA-PRIME-FS] Public Key UE [%s]",uePublicKey.toHexString().c_str());
            m_logger->debug("[EAP-AKA-PRIME-FS] Shared Secret Key [%s]",shared.toHexString().c_str());

            // calculate MK_ECDHE 
            auto mk_ecdhe = keys::CalculateMkECDHE(ckPrime, ikPrime, shared, m_base->config->supi.value());
            m_logger->debug("[EAP-AKA-PRIME-FS] MK ECDHE [%s]",mk_ecdhe.toHexString().c_str());


            // EAP-AKA-Prime FS
             
            // Store the relevant parameters
            m_usim->m_rand = receivedRand.copy();
            m_usim->m_resStar = {};

            // Create new partial native NAS security context and continue with key derivation
            m_usim->m_nonCurrentNsCtx = std::make_unique<NasSecurityContext>();
            m_usim->m_nonCurrentNsCtx->tsc = msg.ngKSI.tsc;
            m_usim->m_nonCurrentNsCtx->ngKsi = msg.ngKSI.ksi;
            // check FS & HPQC Extension 
            m_usim->m_nonCurrentNsCtx->keys.kAusf = keys::CalculateKAusfForEapAkaPrimeFs(mk_ecdhe);
            m_usim->m_nonCurrentNsCtx->keys.abba = msg.abba.rawData.copy();

            keys::DeriveKeysSeafAmf(*m_base->config, currentPlmn, *m_usim->m_nonCurrentNsCtx);

            m_logger->debug("[EAP-AKA-PRIME-FS] K_AUSF [%s]",m_usim->m_nonCurrentNsCtx->keys.kAusf.toHexString().c_str());
            // Send response
            m_nwConsecutiveAuthFailure = 0;
            m_timers->t3520.stop();
            {
                auto *akaPrimeResponse =
                    new eap::EapAkaPrime(eap::ECode::RESPONSE, receivedEap.id, eap::ESubType::AKA_CHALLENGE);
                akaPrimeResponse->attributes.putRes(milenage.res);
                akaPrimeResponse->attributes.putPubECDHE(uePublicKey);
                akaPrimeResponse->attributes.putMac(OctetString::FromSpare(16)); // Dummy mac
                akaPrimeResponse->attributes.putKdf(1);

                // Calculate and put mac value
                auto sendingMac = keys::CalculateMacForEapAkaPrime(kaut, *akaPrimeResponse);
                m_logger->debug("[EAP-AKA-PRIME] AT_MAC [%s]",sendingMac.toHexString().c_str());
                akaPrimeResponse->attributes.replaceMac(sendingMac);

                nas::AuthenticationResponse resp;
                resp.eapMessage = nas::IEEapMessage{};
                resp.eapMessage->eap = std::unique_ptr<eap::EapAkaPrime>(akaPrimeResponse);

                sendNasMessage(resp);
            }
        }
        else if(receivedPubHybrid.length()==1216){
            // EAP-AKA-PRIME with HPQC
            m_logger->debug("[EAP-AKA-PRIME-HPQC]");
            
            uint8_t pk_M[1184];
            uint8_t pk_X[32];
            memcpy(pk_M, receivedPubHybrid.data(), 1184);
            memcpy(pk_X, receivedPubHybrid.data()+1184, 32);


            OctetString octet_pk_M = OctetString::FromArray(pk_M, 1184);
            OctetString octet_pk_X = OctetString::FromArray(pk_X, 32);

            m_logger->debug("[EAP-AKA-PRIME-HPQC][X-WING] pk_M [%s]",octet_pk_M.toHexString().c_str());
            m_logger->debug("[EAP-AKA-PRIME-HPQC][X-WING] pk_X [%s]",octet_pk_X.toHexString().c_str());


            // X25519 
            std::string name("Seed for x25519 generation");
            std::string seed;
            Random rnd = Random::Mixed(name);
            int intLength = sizeof(int32_t);

            for (int i=0; i < (X25519_KEY_SIZE/intLength); i++)
            {
                seed = seed + utils::IntToHex(rnd.nextI());
            }
            OctetString randomSeed = OctetString::FromHex(seed);
            uint8_t ek_X[X25519_KEY_SIZE]; // private
            uint8_t ct_X[X25519_KEY_SIZE]; // public 
            uint8_t ss_X[X25519_KEY_SIZE]; // shared secret

            compact_x25519_keygen(ek_X, ct_X, randomSeed.data());
            OctetString octet_ek_X = OctetString::FromArray(ek_X, X25519_KEY_SIZE);
            OctetString octet_ct_X = OctetString::FromArray(ct_X, X25519_KEY_SIZE);



            compact_x25519_shared(ss_X, octet_ek_X.data(), octet_pk_X.data());
            OctetString octet_ss_X = OctetString::FromArray(ss_X,X25519_KEY_SIZE);

            m_logger->debug("[EAP-AKA-PRIME-HPQC][X-WING] ek_X [%s]",octet_ek_X.toHexString().c_str());
            m_logger->debug("[EAP-AKA-PRIME-HPQC][X-WING] ct_X [%s]",octet_ct_X.toHexString().c_str());
            m_logger->debug("[EAP-AKA-PRIME-HPQC][X-WING] ss_X [%s]",octet_ss_X.toHexString().c_str());

            // ML_KEM
            uint8_t ct_M[1088];
            uint8_t ss_M[32];

            OQS_KEM_ml_kem_768_encaps(ct_M, ss_M, pk_M);

            OctetString octet_ct_M = OctetString::FromArray(ct_M, 1080);
            OctetString octet_ss_M = OctetString::FromArray(ss_M, 32);

            m_logger->debug("[EAP-AKA-PRIME-HPQC][X-WING] ct_M [%s]",octet_ct_M.toHexString().c_str());
            m_logger->debug("[EAP-AKA-PRIME-HPQC][X-WING] ss_M [%s]",octet_ss_M.toHexString().c_str());

            // combiner 
            // ss = Combiner(ss_M, ss_X, ct_X, pk_X)

            /*
            def Combiner(ss_M, ss_X, ct_X, pk_X):
                return SHA3-256(concat(
                    ss_M, 32 64 128+ 6 = 134
                    ss_X, 32
                    ct_X, 32 64 
                    pk_X, 32
                    XWingLabel, 6 
                ))
            */
            uint8_t XWingLabel[6] = {
                0x5c, 0x2e, 0x2f, 0x2f, 0x5e, 0x5c
            };

            uint8_t combiner_output[134];
            memcpy(combiner_output,ss_M, 32);
            memcpy(combiner_output+32,ss_X, 32);
            memcpy(combiner_output+64,ct_X, 32);
            memcpy(combiner_output+96,pk_X, 32);
            memcpy(combiner_output+128,XWingLabel, 6);

            uint8_t shared_secret[32];

            OQS_SHA3_sha3_256(shared_secret,combiner_output,134);

            OctetString octet_shared_secret = OctetString::FromArray(shared_secret, 32);

            m_logger->debug("[EAP-AKA-PRIME-HPQC][X-WING] ss [%s]",octet_shared_secret.toHexString().c_str());

            // ct (1120) = ct_M(1088) + ct_X(32)
            uint8_t ct[1120];
            memcpy(ct,ct_M, 1088);
            memcpy(ct+1088 ,ct_X, 32);

            OctetString octet_ct = OctetString::FromArray(ct, 1120);
            m_logger->debug("[EAP-AKA-PRIME-HPQC][X-WING] ct [%s]",octet_ct.toHexString().c_str());

            // Finish X-WING

            // calculate MK_ECDHE 
            auto mk_ecdhe = keys::CalculateMkECDHE(ckPrime, ikPrime, octet_shared_secret, m_base->config->supi.value());
            m_logger->debug("[EAP-AKA-PRIME-HPQC] MK ECDHE [%s]",mk_ecdhe.toHexString().c_str());
             
            // Store the relevant parameters
            m_usim->m_rand = receivedRand.copy();
            m_usim->m_resStar = {};

            // Create new partial native NAS security context and continue with key derivation
            m_usim->m_nonCurrentNsCtx = std::make_unique<NasSecurityContext>();
            m_usim->m_nonCurrentNsCtx->tsc = msg.ngKSI.tsc;
            m_usim->m_nonCurrentNsCtx->ngKsi = msg.ngKSI.ksi;
            // check FS & HPQC Extension 
            m_usim->m_nonCurrentNsCtx->keys.kAusf = keys::CalculateKAusfForEapAkaPrimeFs(mk_ecdhe);
            m_usim->m_nonCurrentNsCtx->keys.abba = msg.abba.rawData.copy();

            keys::DeriveKeysSeafAmf(*m_base->config, currentPlmn, *m_usim->m_nonCurrentNsCtx);

            m_logger->debug("[EAP-AKA-PRIME-FS] K_AUSF [%s]",m_usim->m_nonCurrentNsCtx->keys.kAusf.toHexString().c_str());
            // Send response
            m_nwConsecutiveAuthFailure = 0;
            m_timers->t3520.stop();
            {
                auto *akaPrimeResponse =
                    new eap::EapAkaPrime(eap::ECode::RESPONSE, receivedEap.id, eap::ESubType::AKA_CHALLENGE);
                akaPrimeResponse->attributes.putRes(milenage.res);
                akaPrimeResponse->attributes.putPubHybrid(octet_ct);
                akaPrimeResponse->attributes.putMac(OctetString::FromSpare(16)); // Dummy mac
                akaPrimeResponse->attributes.putKdf(1);

                // Calculate and put mac value
                auto sendingMac = keys::CalculateMacForEapAkaPrime(kaut, *akaPrimeResponse);
                m_logger->debug("[EAP-AKA-PRIME] AT_MAC [%s]",sendingMac.toHexString().c_str());
                akaPrimeResponse->attributes.replaceMac(sendingMac);

                nas::AuthenticationResponse resp;
                resp.eapMessage = nas::IEEapMessage{};
                resp.eapMessage->eap = std::unique_ptr<eap::EapAkaPrime>(akaPrimeResponse);

                sendNasMessage(resp);
            }
        }
        else if(receivedPubKem.length()==1184){
            // PQC 
            m_logger->debug("[EAP-AKA-PRIME][PQC]");

            uint8_t ct[1088];
            uint8_t ss[32];

            OQS_KEM_ml_kem_768_encaps(ct, ss, receivedPubKem.data());

            OctetString octet_ct = OctetString::FromArray(ct, 1088);
            OctetString octet_ss = OctetString::FromArray(ss, 32);

            m_logger->debug("[EAP-AKA-PRIME][PQC][ML_KEM] ct [%s]",octet_ct.toHexString().c_str());
            m_logger->debug("[EAP-AKA-PRIME][PQC][ML_KEM] ss [%s]",octet_ss.toHexString().c_str());

            // calculate MK_PQ_SHARED_SECRET
            auto mk_pq_shared_secret = keys::CalculateMkPqSharedSecret(ckPrime, ikPrime, octet_ct, octet_ss, m_base->config->supi.value());

            m_logger->debug("[EAP-AKA-PRIME][PQC][ML_KEM] MK_PQ_SHARED_SECRET [%s]",mk_pq_shared_secret.toHexString().c_str());

            // Store the relevant parameters
            m_usim->m_rand = receivedRand.copy();
            m_usim->m_resStar = {};

            // Create new partial native NAS security context and continue with key derivation
            m_usim->m_nonCurrentNsCtx = std::make_unique<NasSecurityContext>();
            m_usim->m_nonCurrentNsCtx->tsc = msg.ngKSI.tsc;
            m_usim->m_nonCurrentNsCtx->ngKsi = msg.ngKSI.ksi;
            // check FS & HPQC & PQC Extension 
            m_usim->m_nonCurrentNsCtx->keys.kAusf = keys::CalculateKAusfForEapAkaPrimeFs(mk_pq_shared_secret);
            m_usim->m_nonCurrentNsCtx->keys.abba = msg.abba.rawData.copy();

            keys::DeriveKeysSeafAmf(*m_base->config, currentPlmn, *m_usim->m_nonCurrentNsCtx);

            m_logger->debug("[EAP-AKA-PRIME][PQC][ML_KEM] K_AUSF [%s]",m_usim->m_nonCurrentNsCtx->keys.kAusf.toHexString().c_str());
            // Send response
            m_nwConsecutiveAuthFailure = 0;
            m_timers->t3520.stop();
            {
                auto *akaPrimeResponse =
                    new eap::EapAkaPrime(eap::ECode::RESPONSE, receivedEap.id, eap::ESubType::AKA_CHALLENGE);
                akaPrimeResponse->attributes.putRes(milenage.res);
                akaPrimeResponse->attributes.putKemCt(octet_ct);
                akaPrimeResponse->attributes.putMac(OctetString::FromSpare(16)); // Dummy mac
                akaPrimeResponse->attributes.putKdf(1);

                // Calculate and put mac value
                auto sendingMac = keys::CalculateMacForEapAkaPrime(kaut, *akaPrimeResponse);
                m_logger->debug("[EAP-AKA-PRIME] AT_MAC [%s]",sendingMac.toHexString().c_str());
                akaPrimeResponse->attributes.replaceMac(sendingMac);

                nas::AuthenticationResponse resp;
                resp.eapMessage = nas::IEEapMessage{};
                resp.eapMessage->eap = std::unique_ptr<eap::EapAkaPrime>(akaPrimeResponse);

                sendNasMessage(resp);
            }


        }
        else{
            // Normal EAP-AKA-Prime 
            // Store the relevant parameters
            m_usim->m_rand = receivedRand.copy();
            m_usim->m_resStar = {};

            // Create new partial native NAS security context and continue with key derivation
            m_usim->m_nonCurrentNsCtx = std::make_unique<NasSecurityContext>();
            m_usim->m_nonCurrentNsCtx->tsc = msg.ngKSI.tsc;
            m_usim->m_nonCurrentNsCtx->ngKsi = msg.ngKSI.ksi;
            m_usim->m_nonCurrentNsCtx->keys.kAusf = keys::CalculateKAusfForEapAkaPrime(mk);
            m_usim->m_nonCurrentNsCtx->keys.abba = msg.abba.rawData.copy();

            keys::DeriveKeysSeafAmf(*m_base->config, currentPlmn, *m_usim->m_nonCurrentNsCtx);

            // Send response
            m_nwConsecutiveAuthFailure = 0;
            m_timers->t3520.stop();
            {
                auto *akaPrimeResponse =
                    new eap::EapAkaPrime(eap::ECode::RESPONSE, receivedEap.id, eap::ESubType::AKA_CHALLENGE);
                akaPrimeResponse->attributes.putRes(milenage.res);
                akaPrimeResponse->attributes.putMac(OctetString::FromSpare(16)); // Dummy mac
                akaPrimeResponse->attributes.putKdf(1);

                // Calculate and put mac value
                auto sendingMac = keys::CalculateMacForEapAkaPrime(kaut, *akaPrimeResponse);
                m_logger->debug("[EAP-AKA-PRIME] AT_MAC [%s]",sendingMac.toHexString().c_str());
                akaPrimeResponse->attributes.replaceMac(sendingMac);

                nas::AuthenticationResponse resp;
                resp.eapMessage = nas::IEEapMessage{};
                resp.eapMessage->eap = std::unique_ptr<eap::EapAkaPrime>(akaPrimeResponse);

                sendNasMessage(resp);
            }
        }

        
    }
    else if (autnCheck == EAutnValidationRes::MAC_FAILURE)
    {
        if (networkFailingTheAuthCheck(true))
            return;
        m_timers->t3520.start();
        sendEapFailure(std::make_unique<eap::EapAkaPrime>(eap::ECode::RESPONSE, receivedEap.id,
                                                          eap::ESubType::AKA_AUTHENTICATION_REJECT));
    }
    else if (autnCheck == EAutnValidationRes::SYNCHRONISATION_FAILURE)
    {
        if (networkFailingTheAuthCheck(true))
            return;

        m_timers->t3520.start();

        auto milenage = calculateMilenage(m_usim->m_sqnMng->getSqn(), receivedRand, true);
        auto auts = keys::CalculateAuts(m_usim->m_sqnMng->getSqn(), milenage.ak_r, milenage.mac_s);

        auto eap = std::make_unique<eap::EapAkaPrime>(eap::ECode::RESPONSE, receivedEap.id,
                                                      eap::ESubType::AKA_SYNCHRONIZATION_FAILURE);
        eap->attributes.putAuts(std::move(auts));
        sendEapFailure(std::move(eap));
    }
    else // the other case, separation bit mismatched
    {
        if (networkFailingTheAuthCheck(true))
            return;
        m_timers->t3520.start();

        auto eap =
            std::make_unique<eap::EapAkaPrime>(eap::ECode::RESPONSE, receivedEap.id, eap::ESubType::AKA_CLIENT_ERROR);
        eap->attributes.putClientErrorCode(0);
        sendEapFailure(std::move(eap));
    }
}

void NasMm::receiveAuthenticationRequest5gAka(const nas::AuthenticationRequest &msg)
{
    Plmn currentPLmn = m_base->shCtx.getCurrentPlmn();
    if (!currentPLmn.hasValue())
        return;

    auto sendFailure = [this](nas::EMmCause cause, std::optional<OctetString> &&auts = std::nullopt) {
        if (cause != nas::EMmCause::SYNCH_FAILURE)
            m_logger->err("Sending Authentication Failure with cause [%s]", nas::utils::EnumToString(cause));
        else
            m_logger->debug("Sending Authentication Failure due to SQN out of range");

        // Clear RAND and RES* stored in volatile memory
        m_usim->m_rand = {};
        m_usim->m_resStar = {};

        // Stop T3516 if running
        m_timers->t3516.stop();

        // Send Authentication Failure
        nas::AuthenticationFailure resp{};
        resp.mmCause.value = cause;

        if (auts.has_value())
        {
            resp.authenticationFailureParameter = nas::IEAuthenticationFailureParameter{};
            resp.authenticationFailureParameter->rawData = std::move(*auts);
        }

        sendNasMessage(resp);
    };

    // ========================== Check the received parameters syntactically ==========================

    if (!msg.authParamRAND.has_value() || !msg.authParamAUTN.has_value())
    {
        sendFailure(nas::EMmCause::SEMANTICALLY_INCORRECT_MESSAGE);
        return;
    }

    if (msg.authParamRAND->value.length() != 16 || msg.authParamAUTN->value.length() != 16)
    {
        sendFailure(nas::EMmCause::SEMANTICALLY_INCORRECT_MESSAGE);
        return;
    }

    // =================================== Check the received ngKSI ===================================

    if (msg.ngKSI.tsc == nas::ETypeOfSecurityContext::MAPPED_SECURITY_CONTEXT)
    {
        m_logger->err("Mapped security context not supported");
        sendFailure(nas::EMmCause::UNSPECIFIED_PROTOCOL_ERROR);
        return;
    }

    if (msg.ngKSI.ksi == nas::IENasKeySetIdentifier::NOT_AVAILABLE_OR_RESERVED)
    {
        m_logger->err("Invalid ngKSI value received");
        sendFailure(nas::EMmCause::UNSPECIFIED_PROTOCOL_ERROR);
        return;
    }

    if ((m_usim->m_currentNsCtx && m_usim->m_currentNsCtx->ngKsi == msg.ngKSI.ksi) ||
        (m_usim->m_nonCurrentNsCtx && m_usim->m_nonCurrentNsCtx->ngKsi == msg.ngKSI.ksi))
    {
        if (networkFailingTheAuthCheck(true))
            return;

        m_timers->t3520.start();
        sendFailure(nas::EMmCause::NGKSI_ALREADY_IN_USE);
        return;
    }

    // ============================================ Others ============================================

    auto &rand = msg.authParamRAND->value;
    auto &autn = msg.authParamAUTN->value;

    EAutnValidationRes autnCheck = EAutnValidationRes::OK;

    // If the received RAND is same with store stored RAND, bypass AUTN validation
    // NOTE: Not completely sure if this is correct and the spec meant this. But in worst case, synchronisation failure
    //  happens, and hopefully that can be restored with the normal resynchronization procedure.
    if (m_usim->m_rand != rand)
    {
        autnCheck = validateAutn(rand, autn);
        m_timers->t3516.start();
    }

    if (autnCheck == EAutnValidationRes::OK)
    {
        // Calculate milenage
        auto milenage = calculateMilenage(m_usim->m_sqnMng->getSqn(), rand, false);
        auto ckIk = OctetString::Concat(milenage.ck, milenage.ik);
        auto sqnXorAk = OctetString::Xor(m_usim->m_sqnMng->getSqn(), milenage.ak);
        auto snn = keys::ConstructServingNetworkName(currentPLmn);

        // Store the relevant parameters
        m_usim->m_rand = rand.copy();
        m_usim->m_resStar = keys::CalculateResStar(ckIk, snn, rand, milenage.res);

        // Create new partial native NAS security context and continue with key derivation
        m_usim->m_nonCurrentNsCtx = std::make_unique<NasSecurityContext>();
        m_usim->m_nonCurrentNsCtx->tsc = msg.ngKSI.tsc;
        m_usim->m_nonCurrentNsCtx->ngKsi = msg.ngKSI.ksi;
        m_usim->m_nonCurrentNsCtx->keys.kAusf = keys::CalculateKAusfFor5gAka(milenage.ck, milenage.ik, snn, sqnXorAk);
        m_usim->m_nonCurrentNsCtx->keys.abba = msg.abba.rawData.copy();

        keys::DeriveKeysSeafAmf(*m_base->config, currentPLmn, *m_usim->m_nonCurrentNsCtx);

        // Send response
        m_nwConsecutiveAuthFailure = 0;
        m_timers->t3520.stop();

        nas::AuthenticationResponse resp;
        resp.authenticationResponseParameter = nas::IEAuthenticationResponseParameter{};
        resp.authenticationResponseParameter->rawData = m_usim->m_resStar.copy();

        sendNasMessage(resp);
    }
    else if (autnCheck == EAutnValidationRes::MAC_FAILURE)
    {
        if (networkFailingTheAuthCheck(true))
            return;
        m_timers->t3520.start();
        sendFailure(nas::EMmCause::MAC_FAILURE);
    }
    else if (autnCheck == EAutnValidationRes::SYNCHRONISATION_FAILURE)
    {
        if (networkFailingTheAuthCheck(true))
            return;

        m_timers->t3520.start();

        auto milenage = calculateMilenage(m_usim->m_sqnMng->getSqn(), rand, true);
        auto auts = keys::CalculateAuts(m_usim->m_sqnMng->getSqn(), milenage.ak_r, milenage.mac_s);
        sendFailure(nas::EMmCause::SYNCH_FAILURE, std::move(auts));
    }
    else // the other case, separation bit mismatched
    {
        if (networkFailingTheAuthCheck(true))
            return;
        m_timers->t3520.start();
        sendFailure(nas::EMmCause::NON_5G_AUTHENTICATION_UNACCEPTABLE);
    }
}

void NasMm::receiveAuthenticationResult(const nas::AuthenticationResult &msg)
{
    if (msg.abba.has_value())
        m_usim->m_nonCurrentNsCtx->keys.abba = msg.abba->rawData.copy();

    if (msg.eapMessage.eap->code == eap::ECode::SUCCESS)
        receiveEapSuccessMessage(*msg.eapMessage.eap);
    else if (msg.eapMessage.eap->code == eap::ECode::FAILURE)
        receiveEapFailureMessage(*msg.eapMessage.eap);
    else
        m_logger->warn("Network sent EAP with an inconvenient type in Authentication Result, ignoring EAP IE.");
}

void NasMm::receiveAuthenticationReject(const nas::AuthenticationReject &msg)
{
    m_logger->err("Authentication Reject received");

    // The RAND and RES* values stored in the ME shall be deleted and timer T3516, if running, shall be stopped
    m_usim->m_rand = {};
    m_usim->m_resStar = {};
    m_timers->t3516.stop();

    if (msg.eapMessage.has_value())
    {
        if (msg.eapMessage->eap->code == eap::ECode::FAILURE)
            receiveEapFailureMessage(*msg.eapMessage->eap);
        else
            m_logger->warn("Network sent EAP with inconvenient type in AuthenticationReject, ignoring EAP IE.");
    }

    // The UE shall set the update status to 5U3 ROAMING NOT ALLOWED,
    switchUState(E5UState::U3_ROAMING_NOT_ALLOWED);
    // Delete the stored 5G-GUTI, TAI list, last visited registered TAI and ngKSI. The USIM shall be considered invalid
    // until switching off the UE or the UICC containing the USIM is removed
    m_storage->storedGuti->clear();
    m_storage->lastVisitedRegisteredTai->clear();
    m_storage->taiList->clear();
    m_usim->m_currentNsCtx = {};
    m_usim->m_nonCurrentNsCtx = {};
    m_usim->invalidate();
    // The UE shall abort any 5GMM signalling procedure, stop any of the timers T3510, T3516, T3517, T3519 or T3521 (if
    // they were running) ..
    m_timers->t3510.stop();
    m_timers->t3516.stop();
    m_timers->t3517.stop();
    m_timers->t3519.stop();
    m_timers->t3521.stop();
    // .. and enter state 5GMM-DEREGISTERED.
    switchMmState(EMmSubState::MM_DEREGISTERED_PS);
}

void NasMm::receiveEapSuccessMessage(const eap::Eap &eap)
{
    // do nothing
}

void NasMm::receiveEapFailureMessage(const eap::Eap &eap)
{
    m_logger->debug("Handling EAP-failure");

    // UE shall delete the partial native 5G NAS security context if any was created
    m_usim->m_nonCurrentNsCtx = {};
}

EAutnValidationRes NasMm::validateAutn(const OctetString &rand, const OctetString &autn)
{
    // Decode AUTN
    OctetString receivedSQNxorAK = autn.subCopy(0, 6);
    OctetString receivedAMF = autn.subCopy(6, 2);
    OctetString receivedMAC = autn.subCopy(8, 8);

    // Check the separation bit
    if (receivedAMF.get(0).bit(7) != 1)
    {
        m_logger->err("AUTN validation SEP-BIT failure. expected: 1, received: 0");
        return EAutnValidationRes::AMF_SEPARATION_BIT_FAILURE;
    }

    // Derive AK and MAC
    auto milenage = calculateMilenage(m_usim->m_sqnMng->getSqn(), rand, false);
    OctetString receivedSQN = OctetString::Xor(receivedSQNxorAK, milenage.ak);

    m_logger->debug("Received SQN [%s]", receivedSQN.toHexString().c_str());
    m_logger->debug("SQN-MS [%s]", m_usim->m_sqnMng->getSqn().toHexString().c_str());

    // Verify that the received sequence number SQN is in the correct range
    bool sqn_ok = m_usim->m_sqnMng->checkSqn(receivedSQN);

    // Re-execute the milenage calculation (if case of sqn is changed with the received value)
    milenage = calculateMilenage(receivedSQN, rand, false);

    // Check MAC
    if (receivedMAC != milenage.mac_a)
    {
        m_logger->err("AUTN validation MAC mismatch. expected [%s] received [%s]", milenage.mac_a.toHexString().c_str(),
                      receivedMAC.toHexString().c_str());
        return EAutnValidationRes::MAC_FAILURE;
    }

    if(!sqn_ok)
        return EAutnValidationRes::SYNCHRONISATION_FAILURE;

    return EAutnValidationRes::OK;
}

crypto::milenage::Milenage NasMm::calculateMilenage(const OctetString &sqn, const OctetString &rand, bool dummyAmf)
{
    OctetString amf = dummyAmf ? OctetString::FromSpare(2) : m_base->config->amf.copy();

    if (m_base->config->opType == OpType::OPC)
        return crypto::milenage::Calculate(m_base->config->opC, m_base->config->key, rand, sqn, amf);

    OctetString opc = crypto::milenage::CalculateOpC(m_base->config->opC, m_base->config->key);
    return crypto::milenage::Calculate(opc, m_base->config->key, rand, sqn, amf);
}

bool NasMm::networkFailingTheAuthCheck(bool hasChance)
{
    if (hasChance && m_nwConsecutiveAuthFailure++ < 3)
        return false;

    // NOTE: Normally if we should check if the UE has an emergency. If it has, it should consider as network passed the
    //  auth check, instead of performing the actions in the following lines. But it's difficult to maintain and
    //  implement this behaviour. Therefore we would expect other solutions for an emergency case. Such as
    //  - Network initiates a Security Mode Command with IA0 and EA0
    //  - UE performs emergency registration after releasing the connection
    // END

    m_logger->err("Network failing the authentication check");

    if (m_cmState == ECmState::CM_CONNECTED)
        localReleaseConnection(true);

    m_timers->t3520.stop();
    return true;
}

} // namespace nr::ue
