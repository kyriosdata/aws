package br.ufg.inf.fs.amazonsqs;

import org.junit.Test;

import static org.junit.Assert.*;

import javax.xml.bind.DatatypeConverter;

/**
 * Created by fabio_000 on 27/03/2014.
 */
public class EncodingTest {

    @Test
    public void testEncodeBase64() throws Exception {

        String msg = "ok";
        String base64 = AmazonUtils.encodeBase64(msg.getBytes());

        byte[] decodificado = DatatypeConverter.parseBase64Binary(base64);
        assertEquals(msg, new String(decodificado));
    }
}
