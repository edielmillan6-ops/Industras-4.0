import cv2
import time
from ultralytics import YOLO

# 1. Cargar el modelo entrenado
model = YOLO("best.pt")

# 2. Iniciar la cámara web
cap = cv2.VideoCapture(0)

# Configurar resolución moderada (mejora el rendimiento)
cap.set(cv2.CAP_PROP_FRAME_WIDTH, 640)
cap.set(cv2.CAP_PROP_FRAME_HEIGHT, 480)

if not cap.isOpened():
    print("Error: No se pudo acceder a la cámara web.")
    exit()

print("Ejecutando inferencia... Presiona 'Esc' o 'q' para salir.")

# Bucle principal de detección
while cap.isOpened():
    ret, frame = cap.read()
    if not ret:
        print("Error al capturar el fotograma.")
        break

    # Realizar inferencia con filtro de confianza (evita falsos positivos y carga innecesaria)
    results = model(frame, conf=0.4, stream=True)

    # Renderizar las anotaciones en el fotograma
    for r in results:
        annotated_frame = r.plot()

    # Mostrar ventana
    cv2.imshow("YOLO Inference", annotated_frame)

    # Pausa ligera (10 ms) para reducir uso de CPU/GPU y evitar sobrecalentamiento
    time.sleep(0.01)

    # Salir al presionar 'Esc' (27) o la tecla 'q'
    key = cv2.waitKey(1) & 0xFF
    if key == 27 or key == ord("q"):
        break

# Liberar recursos de la cámara y cerrar ventanas
cap.release()
cv2.destroyAllWindows()
