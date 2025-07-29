import sys
import os
import json
import matplotlib.pyplot as plt
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QTabWidget, QVBoxLayout, 
    QComboBox, QPushButton, QFileDialog, QTableWidget, QTableWidgetItem,
    QHeaderView, QLabel, QRadioButton, QListWidget, QStackedWidget, QHBoxLayout, QMessageBox,
    QLineEdit, QSpinBox
)
from PyQt5.QtGui import QColor, QKeySequence
from PyQt5.QtCore import Qt
from PyQt5.QtChart import QChart, QChartView, QLineSeries
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        # Set window properties
        self.setWindowTitle("ExeInsight.py")
        self.setGeometry(100, 100, 1200, 800)

        # Create main tab widget
        self.tabWidget = QTabWidget()

        # Create and add tabs
        self.inputTab = QWidget()
        self.initInputTab()
        self.tableTab = QWidget()
        self.initTableTab()
        self.graphTab = QWidget()
        self.initGraphTab()

        self.tabWidget.addTab(self.inputTab, "Input")
        self.tabWidget.addTab(self.tableTab, "Comparison Table")
        self.tabWidget.addTab(self.graphTab, "Graph View")

        # Set central widget
        mainLayout = QVBoxLayout()
        mainLayout.addWidget(self.tabWidget)
        container = QWidget()
        container.setLayout(mainLayout)
        self.setCentralWidget(container)

    def initInputTab(self):
        layout = QVBoxLayout()

        # ComboBox for Option Selection
        self.combo_box = QComboBox()
        self.combo_box.addItem("Single Category")
        self.combo_box.addItem("Multi-Category")
        self.combo_box.currentIndexChanged.connect(self.switch_ui)

        # StackedWidget for option-based UI
        self.stacked_widget = QStackedWidget()
        self.option1_widget = self.create_option1_ui()
        self.option2_widget = self.create_option2_ui()

        self.stacked_widget.addWidget(self.option1_widget)
        self.stacked_widget.addWidget(self.option2_widget)

        # Layout assembly
        layout.addWidget(self.combo_box)
        layout.addWidget(self.stacked_widget)
        self.inputTab.setLayout(layout)

    def create_option1_ui(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)

        # Import and Clear Buttons
        self.import_button = QPushButton("Import JSON File")
        self.import_button.clicked.connect(lambda: self.import_json_file(self.file_list_widget))
        self.clear_button = QPushButton("Clear All")
        self.clear_button.clicked.connect(lambda: self.clear_all_files(self.file_list_widget))
        
        # List and Compare button
        self.file_list_widget = QListWidget()
        self.file_list_widget.setSelectionMode(QListWidget.SingleSelection)  # Allow single selection

        # Connect key press event for deletion
        self.file_list_widget.keyPressEvent = self.delete_item_on_keypress
        

        # Create a horizontal layout for the label and spin box
        threshold_layout = QHBoxLayout()

        # Create the label
        self.label_vt_det = QLabel("VT Detection Threshold:")

        # Create the number entry box (QSpinBox)
        self.threshold_spinbox = QSpinBox()
        self.threshold_spinbox.setMinimum(1)  # Set a minimum value
        self.threshold_spinbox.setMaximum(100)  # Set a maximum value (adjust as needed)
        self.threshold_spinbox.setValue(1)  # Default value


        # Add the label and spin box to the horizontal layout
        layout.addWidget(self.label_vt_det)
        layout.addWidget(self.threshold_spinbox)

        # Add the horizontal layout to the main layout
        layout.addLayout(threshold_layout)

        self.compare_button = QPushButton("Compare Files")
        self.compare_button.clicked.connect(self.compare_files)

        # Add widgets to layout
        layout.addWidget(self.import_button)
        layout.addWidget(self.clear_button)
        layout.addWidget(self.file_list_widget)
        layout.addWidget(self.compare_button)

        return widget

    def create_option2_ui(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)

        # Import and Clear Buttons for both lists
        self.import_button_1 = QPushButton("Import JSON File to Category 1")
        self.import_button_1.clicked.connect(lambda: self.import_json_file(self.file_list_widget_1))
        self.clear_button_1 = QPushButton("Clear All in Category 1")
        self.clear_button_1.clicked.connect(lambda: self.clear_all_files(self.file_list_widget_1))

        self.import_button_2 = QPushButton("Import JSON File to Category 2")
        self.import_button_2.clicked.connect(lambda: self.import_json_file(self.file_list_widget_2))
        self.clear_button_2 = QPushButton("Clear All in Category 2")
        self.clear_button_2.clicked.connect(lambda: self.clear_all_files(self.file_list_widget_2))

        # List widgets for files
        self.file_list_widget_1 = QListWidget()
        self.file_list_widget_1.setSelectionMode(QListWidget.SingleSelection)
        self.file_list_widget_1.keyPressEvent = self.delete_item_on_keypress_option2_1

        self.file_list_widget_2 = QListWidget()
        self.file_list_widget_2.setSelectionMode(QListWidget.SingleSelection)
        self.file_list_widget_2.keyPressEvent = self.delete_item_on_keypress_option2_2

        # Compare button
        self.compare_button_2 = QPushButton("Compare Files in Both Categories")
        self.compare_button_2.clicked.connect(self.compare_files_in_both_lists)

        # Layout assembly
        list1_layout = QVBoxLayout()
        list1_layout.addWidget(self.import_button_1)
        list1_layout.addWidget(self.clear_button_1)
        list1_layout.addWidget(self.file_list_widget_1)

        list2_layout = QVBoxLayout()
        list2_layout.addWidget(self.import_button_2)
        list2_layout.addWidget(self.clear_button_2)
        list2_layout.addWidget(self.file_list_widget_2)

        # Horizontal layout for two lists
        lists_layout = QHBoxLayout()
        lists_layout.addLayout(list1_layout)
        lists_layout.addLayout(list2_layout)

        layout.addLayout(lists_layout)
        layout.addWidget(self.compare_button_2)

        return widget

    def initTableTab(self):
        layout = QVBoxLayout()

        # Inside your __init__ method or setup function
        self.search_bar = QLineEdit(self)
        self.search_bar.setPlaceholderText("Search...")
        self.search_bar.textChanged.connect(self.filter_table)

        layout.addWidget(self.search_bar)

        # Table Widget
        self.tableWidget = QTableWidget()
        self.tableWidget.setColumnCount(3)
        self.tableWidget.setHorizontalHeaderLabels(["Key", "Category 1 Value", "Category 2 Value"])
        self.tableWidget.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        layout.addWidget(self.tableWidget)
        self.tableTab.setLayout(layout)

    def initGraphTab(self):
        layout = QVBoxLayout()

        # Create a ComboBox for selecting the graph type
        self.graph_type_combo = QComboBox()
        self.graph_type_combo.addItems(["Bar", "Line", "Pie", "Scatter"])
        self.graph_type_combo.currentIndexChanged.connect(self.update_graph_type)

        # Create a new Figure and Canvas for the main graph
        self.figure = Figure(figsize=(12, 6))  # Store reference to the figure
        self.canvas = FigureCanvas(self.figure)  # Create the canvas for the graph

        # Create a navigation toolbar
        from matplotlib.backends.backend_qt5agg import NavigationToolbar2QT as NavigationToolbar
        self.toolbar = NavigationToolbar(self.canvas, self)  # Create the toolbar

        # Add the toolbar and canvas to the layout
        layout.addWidget(self.toolbar)  # Add the navigation toolbar
        layout.addWidget(self.graph_type_combo)  # Add the graph type ComboBox
        layout.addWidget(self.canvas)    # Add the canvas to the graph layout

        # Set the layout to the main graph tab
        self.graphTab.setLayout(layout)

    def switch_ui(self, index):
        """Switch UI based on ComboBox selection."""
        self.stacked_widget.setCurrentIndex(index)

    def import_json_file(self, list_widget):
        """Select JSON files and add them to the specified list widget."""
        file_dialog = QFileDialog()
        file_dialog.setFileMode(QFileDialog.ExistingFiles)
        file_dialog.setNameFilter("JSON Files (*.json)")

        # Set the initial directory
        initial_directory = "./output"  # Change this to your desired path
        file_dialog.setDirectory(initial_directory)

        if file_dialog.exec_():
            selected_files = file_dialog.selectedFiles()
            for file in selected_files:
                if not any(file == list_widget.item(i).text() for i in range(list_widget.count())):
                    list_widget.addItem(file)

    def clear_all_files(self, list_widget):
        """Clear all files from the specified list widget."""
        list_widget.clear()

    def delete_item_on_keypress(self, event):
        """Delete selected item from the list widget on key press."""
        if event.key() in (Qt.Key_Delete, Qt.Key_Backspace):
            selected_items = self.file_list_widget.selectedItems()
            for item in selected_items:
                self.file_list_widget.takeItem(self.file_list_widget.row(item))

    def delete_item_on_keypress_option2_1(self, event):
        """Delete selected item from Category 1 in Option 2 on key press."""
        if event.key() in (Qt.Key_Delete, Qt.Key_Backspace):
            selected_items = self.file_list_widget_1.selectedItems()
            for item in selected_items:
                self.file_list_widget_1.takeItem(self.file_list_widget_1.row(item))

    def delete_item_on_keypress_option2_2(self, event):
        """Delete selected item from Category 2 in Option 2 on key press."""
        if event.key() in (Qt.Key_Delete, Qt.Key_Backspace):
            selected_items = self.file_list_widget_2.selectedItems()
            for item in selected_items:
                self.file_list_widget_2.takeItem(self.file_list_widget_2.row(item))

    def compare_files(self):
        """Compare files in Option 1 and update table and graph."""
        files = [self.file_list_widget.item(i).text() for i in range(self.file_list_widget.count())]
        vt_det = self.threshold_spinbox.value()  # Get the value from the QSpinBox
        self.analyze_files(files, [], vt_det)
        self.tabWidget.setCurrentIndex(1)

    def compare_files_in_both_lists(self):
        """Compare files in both lists in Option 2 and update table and graph."""
        files1 = [self.file_list_widget_1.item(i).text() for i in range(self.file_list_widget_1.count())]
        files2 = [self.file_list_widget_2.item(i).text() for i in range(self.file_list_widget_2.count())]
        self.analyze_files(files1, files2)
        self.tabWidget.setCurrentIndex(1)

    def analyze_files(self, group1_files, group2_files, vt_det=0):
        """Analyze and populate the comparison table and graph."""
        metrics_table = {}
        metrics_graph = {}
        averages_group1_table = {}
        averages_group2_table = {}
        averages_group1_graph = {}
        averages_group2_graph = {}
        all_keys_table = set()
        all_keys_graph = set()
        threshold = vt_det  # Define a threshold for splitting (modify as needed)

        # If only one group is provided, split it based on vt_detections
        if not group2_files:
            group2_files = [f for f in group1_files if json.load(open(f)).get('vt_detections', 0) >= threshold]
            group1_files = [f for f in group1_files if json.load(open(f)).get('vt_detections', 0) < threshold]

        # Process each file and extract metrics for both table and graph
        for file_path in group1_files + group2_files:
            with open(file_path, 'r') as file:
                data = json.load(file)
                metrics_table[file_path] = data  # Store for table view
                metrics_graph[file_path] = data  # Store for graph view

        # Process data for the table, capturing all keys
        for file_path, data in metrics_table.items():
            self.process_all_keys_for_table(file_path, "", data, group1_files, averages_group1_table, averages_group2_table, all_keys_table)

        # Process data for the graph, capturing only top-level keys with 'imports' values if available
        for file_path, data in metrics_graph.items():
            for key, value in data.items():
                if isinstance(value, dict) and 'imports' in value:
                    # Use the 'imports' value if the top-level key has an 'imports' field
                    imports_value = value['imports']
                    all_keys_graph.add(key)
                    if file_path in group1_files:
                        if key not in averages_group1_graph:
                            averages_group1_graph[key] = []
                        averages_group1_graph[key].append(imports_value)
                    else:
                        if key not in averages_group2_graph:
                            averages_group2_graph[key] = []
                        averages_group2_graph[key].append(imports_value)
                elif isinstance(value, (int, float)):
                    # For simple numeric values at the top level, use the value directly
                    all_keys_graph.add(key)
                    if file_path in group1_files:
                        if key not in averages_group1_graph:
                            averages_group1_graph[key] = []
                        averages_group1_graph[key].append(value)
                    else:
                        if key not in averages_group2_graph:
                            averages_group2_graph[key] = []
                        averages_group2_graph[key].append(value)

        # Populate the table with averages for each key
        self.populate_table(all_keys_table, averages_group1_table, averages_group2_table)
        # Plot only the top-level data with imports or direct values for the graph
        self.plot_graph(averages_group1_graph, averages_group2_graph)


    def process_all_keys_for_table(self, file_path, parent_key, data, group1_files, averages_group1, averages_group2, all_keys):
        """Recursively process all keys for the table view."""
        for key, value in data.items():
            full_key = f"{parent_key}.{key}" if parent_key else key
            if isinstance(value, dict):
                # Recurse into nested dictionaries
                self.process_all_keys_for_table(file_path, full_key, value, group1_files, averages_group1, averages_group2, all_keys)
            else:
                all_keys.add(full_key)
                # Add the full key to the correct group based on file_path
                if file_path in group1_files:
                    if full_key not in averages_group1:
                        averages_group1[full_key] = []
                    if isinstance(value, (int, float)):
                        averages_group1[full_key].append(value)
                else:
                    if full_key not in averages_group2:
                        averages_group2[full_key] = []
                    if isinstance(value, (int, float)):
                        averages_group2[full_key].append(value)


    def populate_table(self, all_keys, averages_group1, averages_group2):
        """Populate the table with averages for each key."""
        self.tableWidget.setRowCount(len(all_keys))
        row = 0
        for key in all_keys:
            self.tableWidget.setItem(row, 0, QTableWidgetItem(key))
            avg_group1 = (sum(averages_group1[key]) / len(averages_group1[key])) if averages_group1.get(key) else 0
            avg_group2 = (sum(averages_group2[key]) / len(averages_group2[key])) if averages_group2.get(key) else 0
            self.tableWidget.setItem(row, 1, QTableWidgetItem(str(avg_group1)))
            self.tableWidget.setItem(row, 2, QTableWidgetItem(str(avg_group2)))

            # Color coding logic
            if avg_group1 < avg_group2:
                self.tableWidget.item(row, 1).setBackground(QColor('lightgreen'))  # Group 1 is lower
                self.tableWidget.item(row, 2).setBackground(QColor('lightcoral'))   # Group 2 is higher
            elif avg_group1 > avg_group2:
                self.tableWidget.item(row, 1).setBackground(QColor('lightcoral'))   # Group 1 is higher
                self.tableWidget.item(row, 2).setBackground(QColor('lightgreen'))   # Group 2 is lower
            else:
                self.tableWidget.item(row, 1).setBackground(QColor('lightgray'))    # Equal values
                self.tableWidget.item(row, 2).setBackground(QColor('lightgray'))    # Equal values

            row += 1

        self.tableWidget.setSortingEnabled(True)  # Enable sorting

    def filter_table(self):
        """Filter the table based on the search bar input."""
        search_text = self.search_bar.text().lower()  # Get the search text
        for row in range(self.tableWidget.rowCount()):
            item = self.tableWidget.item(row, 0)  # Assume we're filtering by the first column (keys)
            if item:
                if search_text in item.text().lower():  # Check if search text is in the item text
                    self.tableWidget.showRow(row)  # Show matching row
                else:
                    self.tableWidget.hideRow(row)  # Hide non-matching row

    def plot_graph(self, averages_group1, averages_group2):
        """Plot the comparison graph in the graph view tab."""
        
        # Ensure the graph view tab is selected
        self.tabWidget.setCurrentIndex(2)  # Assuming the graph view is at index 2

        # Get all unique keys and their average values
        all_keys = sorted(set(averages_group1.keys()).union(averages_group2.keys()))
        values_group1 = [sum(averages_group1[key]) / len(averages_group1[key]) if averages_group1.get(key) else 0 for key in all_keys]
        values_group2 = [sum(averages_group2[key]) / len(averages_group2[key]) if averages_group2.get(key) else 0 for key in all_keys]

        # Clear any previous plot from the figure
        self.figure.clf()  # Clear the figure

        # Determine the selected graph type
        graph_type = self.graph_type_combo.currentText()

        # Create a plot based on the selected graph type
        ax = self.figure.add_subplot(111)
        x = range(len(all_keys))

        if graph_type == "Bar":
            width = 0.35  # Width of the bars
            ax.bar([i - width / 2 for i in x], values_group1, width, label='Category 1', color='skyblue')
            ax.bar([i + width / 2 for i in x], values_group2, width, label='Category 2', color='salmon')
            ax.set_ylabel('Average within Category')
            ax.set_title('Bar Graph')

        elif graph_type == "Line":
            ax.plot(x, values_group1, marker='o', label='Category 1', color='skyblue')
            ax.plot(x, values_group2, marker='o', label='Category 2', color='salmon')
            ax.set_ylabel('Average within Category')
            ax.set_title('Line Graph')

        elif graph_type == "Pie":
            # Plotting a pie chart (only for one category as pie charts usually represent one dataset)
            ax.pie(values_group1, labels=all_keys, autopct='%1.1f%%', startangle=140)
            ax.set_title('Pie Chart for Category 1')

        elif graph_type == "Scatter":
            ax.scatter(x, values_group1, label='Category 1', color='skyblue')
            ax.scatter(x, values_group2, label='Category 2', color='salmon')
            ax.set_ylabel('Average within Category')
            ax.set_title('Scatter Plot')

        # Label and customize the plot
        ax.set_xticks(x)
        ax.set_xticklabels(all_keys, rotation=45, ha='right', fontsize=10)  # Adjust label rotation and size
        ax.legend()

        # Use tight layout to make sure everything fits without overlapping
        self.figure.tight_layout(pad=3.0)  # Add padding if necessary

        # Draw the canvas
        self.canvas.draw()  # Refresh the canvas
        
    def update_graph_type(self):
        """Update the graph when the graph type is changed."""
        # Call plot_graph with existing averages
        self.plot_graph(self.averages_group1_graph, self.averages_group2_graph)


def main():
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())

if __name__ == '__main__':
    main()
