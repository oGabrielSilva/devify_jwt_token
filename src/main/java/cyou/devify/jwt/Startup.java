package cyou.devify.jwt;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;

@SpringBootApplication
public class Startup {
	@Value("${server.port}")
	int port;

	@EventListener(ApplicationReadyEvent.class)
	public void ready() {
		System.out.println(String.format("\nApplication on http://127.0.0.1:%d\n", port));
	}

	public static void main(String[] args) {
		SpringApplication.run(Startup.class, args);
	}

}
