package br.ufg.inf.fs.amazonsqs;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import java.security.SignatureException;

/**
 * Métodos de conveniência para interação com
 * Amazon SQS via Queue API.
 */
public class AmazonUtils {

    private static final String HMACSHA1 = "HmacSHA1";

    /**
     * Produz assinatura dos dados empregando o 
     * algoritmo HMAC SHA.
     * @param dados Os dados para os quais a assinatura
     *              será produzida.
     * @param secretAccessKey A chave secreta a ser empregada no processo
     *            de assinatura.
     * @return A assinatura HMAC SHA1 dos dados de entrada fornecidos
     * empregando a chave indicada.
     * @throws SignatureException Na presença de exceção
     * no processo de assinatura.
     */
    public static String calculaHmacSha(String dados, String secretAccessKey)
            throws SignatureException {

        String assinatura;
        try {
            byte[] sak = secretAccessKey.getBytes();
            SecretKeySpec signingKey = new SecretKeySpec(sak, HMACSHA1);

            Mac mac = Mac.getInstance(HMACSHA1);
            mac.init(signingKey);

            byte[] rawHmac = mac.doFinal(dados.getBytes());

            assinatura = encodeBase64(rawHmac);

        } catch (Exception e) {
            throw new SignatureException("Assinatura não gerada : " + e.getMessage());
        }

        return assinatura;
    }

    /**
     * Produz BASE64 a partir do vetor fornecido.
     *
     * @param entrada A entrada a ser convertida para a BASE64.
     * @return Sequência de caracteres na BASE64, correspondente
     * à entrada fornecida.
     */
    public static String encodeBase64(byte[] entrada) {
        return DatatypeConverter.printBase64Binary(entrada);
    }
}
