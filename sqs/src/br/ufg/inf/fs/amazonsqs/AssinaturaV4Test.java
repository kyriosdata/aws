package br.ufg.inf.fs.amazonsqs;

import org.junit.Test;

import java.io.UnsupportedEncodingException;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Calendar;
import java.util.Date;

import static org.junit.Assert.*;

public class AssinaturaV4Test {

    @Test
    public void testCanonicalUriCasoTipico() throws Exception {
        String queueUrl = "http://sqs.us-east-1.amazonaws.com/12/testQueue/";
        String host = "sqs.us-east-1.amazonaws.com";

        assertEquals("/12/testQueue/", AssinaturaV4.canonicalUri(queueUrl, host));
    }

    @Test
    public void testCanonicalUriSemPathSemBarra() throws Exception {
        String queueUrl = "http://sqs.us-east-1.amazonaws.com";
        String host = "sqs.us-east-1.amazonaws.com";

        assertEquals("/", AssinaturaV4.canonicalUri(queueUrl, host));
    }

    @Test
    public void testCanonicalUriSemPathComBarra() throws Exception {
        String queueUrl = "http://sqs.us-east-1.amazonaws.com/";
        String host = "sqs.us-east-1.amazonaws.com";

        assertEquals("/", AssinaturaV4.canonicalUri(queueUrl, host));
    }

    @Test
    public void headersObrigatoriosFixosSqs() throws Exception {
        AssinaturaV4 av4 = new AssinaturaV4("http://sqs.ea-east-1.amazonaws.com");

        String ch = av4.payload("")
                .host("sqs.ea-east-1.amazonaws.com")
                .regiao("ea-east-1")
                .canonicalHeaders();

        assertTrue(ch.contains("content-type"));
        assertTrue(ch.contains("x-amz-date"));
        assertTrue(ch.contains("host"));
    }

    @Test
    public void signedHeadersFixosSqs() throws Exception {

        assertEquals("content-type;host;x-amz-date", AssinaturaV4.signedHeaders());
    }

    @Test
    public void formatoDeDataConformeEsperadoApenasOitoCaracteres() {
        final Date agora = new Date();

        Calendar c = Calendar.getInstance();
        c.setTime(agora);

        int ano = c.get(Calendar.YEAR);
        int mes = c.get(Calendar.MONTH) + 1;
        int dia = c.get(Calendar.DAY_OF_MONTH);

        String yyyymmdd = "" + ano +
                (mes < 10 ? "0" + mes : mes) +
                (dia < 10 ? "0" + dia : dia);

        AssinaturaV4 av4 = new AssinaturaV4("");

        assertEquals(yyyymmdd, av4.dataEmOitoDigitos());
    }

    @Test
    public void conversaoParaHexadecimal() throws UnsupportedEncodingException {
        assertEquals("00", AssinaturaV4.toHex(new byte[]{0}));
        assertEquals("01", AssinaturaV4.toHex(new byte[]{1}));
        assertEquals("0f", AssinaturaV4.toHex(new byte[]{15}));
        assertEquals("0a", AssinaturaV4.toHex(new byte[]{10}));
        assertEquals("6d", AssinaturaV4.toHex(new byte[]{109}));
    }

    @Test
    public void sha256ImplementadoCorretamente() {
        byte[] sha256 = AssinaturaV4.sha256("Action=ListUsers&Version=2010-05-08");
        String hex = AssinaturaV4.toHex(sha256);

        assertEquals("b6359072c78d70ebee1e81adcbab4f01bf2c23245fa365ef83fe8f1f955085e2", hex);
    }

    @Test
    public void testeAdicionalDeHashEmHexadecimal() {
        String requisicaoCanonica = "POST\n" +
                "/\n" +
                "\n" +
                "content-type:application/x-www-form-urlencoded; charset=utf-8\n" +
                "host:iam.amazonaws.com\n" +
                "x-amz-date:20110909T233600Z\n" +
                "\n" +
                "content-type;host;x-amz-date\n" +
                "b6359072c78d70ebee1e81adcbab4f01bf2c23245fa365ef83fe8f1f955085e2";

        byte[] hash256 = AssinaturaV4.sha256(requisicaoCanonica);
        String emHexa = AssinaturaV4.toHex(hash256);

        assertEquals("3511de7e95d28ecd39e9513b642aee07e54f4941150d8df8bf94b328ef7e55e2", emHexa);
    }

    // Teste abaixo considera apenas o primeiro byte do exemplo disponível em
    // http://docs.aws.amazon.com/general/latest/gr/sigv4-calculate-signature.html
    @Test
    public void assinaturaMontagemCorreta() throws Exception {
        String chaveSecreta = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
        byte[] key = AssinaturaV4.getSigningKey(chaveSecreta, "20110909", "us-east-1", "iam");

        String hex = AssinaturaV4.toHex(key);
        int valor = Integer.parseInt(hex.substring(0, 2));
        assertEquals(98, valor);
    }

    @Test
    public void exibeRequisicaoCanonica() {
        AssinaturaV4 av4 = new AssinaturaV4("http://sqs.sa-east-1.amazonsqs.com");
        av4.host("sqs.sa-east-1.amazonaws.com").payload("");

        System.out.println(av4.canonicalRequest());
    }

    @Test
    public void experimentos() {
        final AssinaturaV4 v4 = new AssinaturaV4("http://sqs.sa-east-1.amazonaws.com/")
                .host("sqs.sa-east-1.amazonaws.com")
                .regiao("sa-east-1")
                .payload("")
                .servico("sqs");

        System.out.println(v4.stringToSign());
    }
}
